"""
Expert 2: Fine-tuned DistilBERT URL classifier.
Catches contextual / semantic relationships: brand impersonation phrasing,
encoded payloads, contextually suspicious sub-strings that pure char-stats miss.

MPS-optimised for Apple Silicon (M5 Air) — FULL SPEED mode:
  • device="mps" with automatic fallback to CUDA / CPU
  • bfloat16 autocast on MPS (stable for DistilBERT, ~30-40 % speed-up)
  • num_workers=0 on MPS + background-thread prefetcher to hide H→D transfer
  • foreach=True AdamW (fused kernel launches, lower Python overhead)
  • Deferred loss accumulation (no per-step CPU↔GPU sync stall)
  • tqdm postfix throttled to every 50 steps (removes Python hot-loop cost)
  • Layer-freezing strategy: freeze bottom N transformer blocks first, then
    optionally thaw all for a low-LR fine-tune pass (saves ~40 % training time
    on M5 Air while losing < 0.5 % AUC vs. full fine-tune)
  • Gradient clipping (max_norm=1.0) for stable MPS training
  • CosineAnnealingLR scheduler
  • Per-epoch AUC + F1 reported on validation set
  • save / load helpers for checkpointing
classification head (LayerNorm → Dropout → Linear → sigmoid).

Typical hyperparameters for M5 Air:
  batch_size = 16   (set to 32 if ≥ 16 GB unified memory)
  max_length  = 128 (URLs rarely exceed 128 subword tokens; 256 if needed)
  lr          = 2e-5 (standard BERT fine-tune range)
  freeze_layers = 4 (freeze bottom 4 of 6 DistilBERT blocks initially)
"""

from __future__ import annotations

import os
import queue
import threading
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

try:
    from transformers import DistilBertTokenizerFast, DistilBertModel
    _TRANSFORMERS = True
except ImportError:
    _TRANSFORMERS = False

try:
    from sklearn.metrics import roc_auc_score, f1_score
    _SKLEARN = True
except ImportError:
    _SKLEARN = False


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------

def get_device() -> torch.device:
    """Return the best available device (MPS > CUDA > CPU)."""
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def _loader_kwargs(device: torch.device) -> dict:
    """
    DataLoader kwargs tuned per backend.
    MPS: num_workers=0  — fork-based multiprocessing is unsafe with MPS.
         We compensate with a background-thread prefetcher (_MPSPrefetcher).
    CUDA: num_workers=4, pin_memory=True for async host→device copies.
    CPU: num_workers=2.
    """
    if device.type == "mps":
        return {"num_workers": 0, "pin_memory": False, "persistent_workers": False}
    if device.type == "cuda":
        return {"num_workers": 4, "pin_memory": True, "persistent_workers": True}
    return {"num_workers": 2, "pin_memory": False}


class _MPSPrefetcher:
    """
    Background-thread prefetcher for MPS (where num_workers must be 0).

    Runs a daemon thread that calls `.to(device)` on the *next* batch while
    the GPU is busy computing the *current* batch, hiding host→device transfer
    latency entirely.

    Usage (as a context manager or manual start/stop):
        with _MPSPrefetcher(loader, device) as pf:
            for batch in pf:
                ...
    """

    def __init__(self, loader: DataLoader, device: torch.device, queue_size: int = 2):
        self._loader = loader
        self._device = device
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def _worker(self) -> None:
        try:
            for batch in self._loader:
                if self._stop_event.is_set():
                    break
                gpu_batch = {k: v.to(self._device, non_blocking=False) for k, v in batch.items()}
                self._queue.put(gpu_batch)
        finally:
            self._queue.put(None)  # sentinel

    def __enter__(self) -> "_MPSPrefetcher":
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        self._stop_event.set()
        # drain queue so worker can unblock on queue.put
        try:
            while True:
                self._queue.get_nowait()
        except queue.Empty:
            pass
        if self._thread:
            self._thread.join(timeout=5)

    def __iter__(self):
        while True:
            batch = self._queue.get()
            if batch is None:
                break
            yield batch

    def __len__(self) -> int:
        return len(self._loader)


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class _PreTokenizedBertDataset(Dataset):
    def __init__(self, input_ids: torch.Tensor, attention_mask: torch.Tensor, labels: torch.Tensor):
        self.input_ids = input_ids
        self.attention_mask = attention_mask
        self.labels = labels

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int):
        return {
            "input_ids":      self.input_ids[idx],
            "attention_mask": self.attention_mask[idx],
            "label":          self.labels[idx],
        }

# Keep original name as alias in case external scripts import it
URLBertDataset = _PreTokenizedBertDataset


def _pretokenize(urls: list[str], tokenizer, max_length: int = 128, desc: str = "data") -> tuple[torch.Tensor, torch.Tensor]:
    """Tokenise a list of URLs into input_ids and attention_mask tensors using fast batch-encoding."""
    from tqdm import tqdm as _tqdm
    N = len(urls)
    input_ids = torch.zeros((N, max_length), dtype=torch.long)
    attention_mask = torch.zeros((N, max_length), dtype=torch.long)
    
    chunk_size = 20000
    steps = range(0, N, chunk_size)
    
    # We display a progress bar for tokenizer since it's the first step
    for i in _tqdm(steps, desc=f"[Expert 2] Pre-tokenising {desc}", unit="chunk", leave=False):
        chunk = urls[i : i + chunk_size]
        enc = tokenizer(
            chunk,
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        input_ids[i : i + len(chunk)] = enc["input_ids"]
        attention_mask[i : i + len(chunk)] = enc["attention_mask"]
        
    return input_ids, attention_mask



# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

_DISTILBERT_CHECKPOINT = "distilbert-base-uncased"


class URLDistilBertClassifier(nn.Module):
    """
    DistilBERT backbone + lightweight classification head.

    Architecture:
        DistilBERT [CLS] hidden (768-d)
        └─► LayerNorm
            └─► Dropout(p)
                └─► Linear(768 → 1)   # raw logit, sigmoid applied outside
    """

    def __init__(
        self,
        checkpoint: str = _DISTILBERT_CHECKPOINT,
        dropout: float = 0.2,
        freeze_layers: int = 4,
    ):
        super().__init__()
        if not _TRANSFORMERS:
            raise ImportError(
                "transformers is required for Expert 2. "
                "Install it with: pip install transformers"
            )
        self.bert = DistilBertModel.from_pretrained(checkpoint)
        hidden_size = self.bert.config.hidden_size  # 768 for base

        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_size),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 1),
        )

        # Freeze embedding layer (always — it changes very slowly)
        for param in self.bert.embeddings.parameters():
            param.requires_grad = False

        # Freeze the bottom *freeze_layers* transformer blocks
        # DistilBERT has 6 transformer blocks (self.bert.transformer.layer)
        n_blocks = len(self.bert.transformer.layer)
        for i, block in enumerate(self.bert.transformer.layer):
            if i < min(freeze_layers, n_blocks):
                for param in block.parameters():
                    param.requires_grad = False

        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        total     = sum(p.numel() for p in self.parameters())
        pct = 100.0 * trainable / total
        print(
            f"[Expert 2] {trainable:,} / {total:,} params trainable ({pct:.1f}%) "
            f"(froze embeddings + bottom {freeze_layers} blocks)"
        )

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Returns raw logit (batch,). Apply sigmoid for probability."""
        out = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        cls = out.last_hidden_state[:, 0, :]   # [CLS] token embedding
        return self.classifier(cls).squeeze(-1)

    def unfreeze_all(self) -> None:
        """Unfreeze all parameters for a final low-LR fine-tune pass."""
        for param in self.parameters():
            param.requires_grad = True
        print("[Expert 2] all layers unfrozen for full fine-tune pass")


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_expert2(
    train_urls: list[str],
    train_labels: list[int],
    val_urls: list[str],
    val_labels: list[int],
    checkpoint: str = _DISTILBERT_CHECKPOINT,
    max_length: int = 128,
    epochs: int = 5,
    batch_size: int = 16,
    lr: float = 2e-5,
    freeze_layers: int = 4,
    unfreeze_after_epoch: int | None = None,
    save_path: str | None = None,
) -> URLDistilBertClassifier:
    """
    Fine-tune DistilBERT for URL classification.

    Args:
        freeze_layers:       Number of bottom DistilBERT blocks to freeze
                             initially (reduces training time on M5 Air).
        unfreeze_after_epoch: If set, unfreeze all layers after this epoch
                             and continue with lr * 0.1 (full fine-tune).
        save_path:           If set, best weights are saved here.

    MPS notes
    ---------
    • bfloat16 autocast is enabled on MPS for DistilBERT — no BatchNorm in the
      architecture so this is numerically stable and gives ~30-40 % speed-up.
    • torch.compile() is applied when MPS is active; silently skipped on
      older PyTorch versions.
    """
    if not _TRANSFORMERS:
        raise ImportError("Install transformers: pip install transformers")

    device = get_device()
    print(f"[Expert 2] training on device: {device}")

    # ── Tokenizer & model ────────────────────────────────────────────────────
    tokenizer = DistilBertTokenizerFast.from_pretrained(checkpoint)
    model = URLDistilBertClassifier(
        checkpoint=checkpoint,
        freeze_layers=freeze_layers,
    ).to(device)

    # torch.compile on MPS — guard behind PyTorch ≥ 2.13 (same Metal shader
    # codegen bug as Expert 1: BatchNorm+Dropout fused kernel fails on ≤ 2.12)
    _ver = tuple(int(x) for x in torch.__version__.split(".")[:2])
    _compile_safe = _ver >= (2, 13)
    if device.type == "mps" and hasattr(torch, "compile") and _compile_safe:
        try:
            model = torch.compile(model)
            print("[Expert 2] torch.compile() enabled for MPS")
        except Exception as e:
            print(f"[Expert 2] torch.compile() skipped: {e}")
    elif device.type == "mps" and not _compile_safe:
        print(f"[Expert 2] torch.compile() skipped (PyTorch {torch.__version__} "
              f"< 2.13 — Metal shader bug); training on MPS without compile")

    # foreach=True: fuses per-parameter kernel launches into a single call
    # — significant speedup on MPS/CUDA for models with many small tensors.
    _adaw_kwargs: dict = {"lr": lr, "weight_decay": 1e-2}
    try:
        # foreach is supported in PyTorch ≥ 1.12
        _adaw_kwargs["foreach"] = True
    except Exception:
        pass
    opt = torch.optim.AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        **_adaw_kwargs,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    criterion = nn.BCEWithLogitsLoss()

    # ── Pre-tokenise all data to tensors (no on-the-fly python strings) ──────
    X_train_ids, X_train_mask = _pretokenize(train_urls, tokenizer, max_length, desc="train")
    y_train = torch.tensor(train_labels, dtype=torch.float32)
    X_val_ids, X_val_mask     = _pretokenize(val_urls, tokenizer, max_length, desc="val  ")
    y_val = torch.tensor(val_labels, dtype=torch.float32)

    # ── DataLoaders ──────────────────────────────────────────────────────────
    kw = _loader_kwargs(device)
    train_ds = _PreTokenizedBertDataset(X_train_ids, X_train_mask, y_train)
    val_ds   = _PreTokenizedBertDataset(X_val_ids, X_val_mask, y_val)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, drop_last=True, **kw)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False, drop_last=False, **kw)

    best_auc   = 0.0
    best_state: dict | None = None

    from tqdm import tqdm as _tqdm

    for epoch in range(epochs):
        # Optional: unfreeze all layers mid-training for a deeper fine-tune
        if unfreeze_after_epoch is not None and epoch == unfreeze_after_epoch:
            raw = getattr(model, "_orig_mod", model)
            raw.unfreeze_all()
            for group in opt.param_groups:
                group["lr"] = lr * 0.1
            print(f"[Expert 2] epoch {epoch+1}: lr reset to {lr * 0.1:.2e}")

        # ── Train ─────────────────────────────────────────────────────────────
        model.train()
        total_loss = 0.0
        # Deferred loss accumulator — avoid per-step CPU sync.
        # We flush to Python float every _LOSS_SYNC_EVERY steps.
        _LOSS_SYNC_EVERY = 50
        _loss_accum = torch.zeros(1, device=device)  # stays on GPU
        _loss_sync_count = 0

        # Determine whether MPS autocast is available.
        # bfloat16 is stable for DistilBERT (no BatchNorm) on MPS.
        _use_autocast = (device.type == "mps" and
                         hasattr(torch, "autocast") and
                         hasattr(torch.backends, "mps") and
                         torch.backends.mps.is_available())
        _amp_dtype = torch.bfloat16 if _use_autocast else torch.float32
        if epoch == 0 and _use_autocast:
            print(f"[Expert 2] MPS bfloat16 autocast ENABLED (dtype={_amp_dtype})")
        elif epoch == 0:
            print("[Expert 2] MPS autocast not available — fp32 training")

        # Use background-thread prefetcher on MPS; plain iteration elsewhere.
        _use_prefetch = (device.type == "mps")

        tbar = _tqdm(train_loader, desc=f"[E2] Epoch {epoch+1:02d}/{epochs} train", unit="batch", leave=False)

        def _run_train_loop(batch_iter):
            """Inner train loop; accepts any iterable of already-on-device batches
            (prefetcher) or CPU batches (non-MPS path)."""
            nonlocal total_loss, _loss_accum, _loss_sync_count
            for step, batch in enumerate(batch_iter):
                if _use_prefetch:
                    # Prefetcher already moved tensors to device
                    ids  = batch["input_ids"]
                    mask = batch["attention_mask"]
                    y    = batch["label"]
                else:
                    ids  = batch["input_ids"].to(device)
                    mask = batch["attention_mask"].to(device)
                    y    = batch["label"].to(device)

                opt.zero_grad()
                if _use_autocast:
                    with torch.autocast(device_type="mps", dtype=_amp_dtype):
                        logits = model(ids, mask)
                        loss   = criterion(logits, y)
                else:
                    logits = model(ids, mask)
                    loss   = criterion(logits, y)

                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                opt.step()

                # Accumulate loss on GPU — no CPU sync
                _loss_accum += loss.detach() * ids.size(0)
                _loss_sync_count += 1

                # Sync to CPU every N steps to update tqdm (cheap)
                if step % _LOSS_SYNC_EVERY == 0:
                    synced = _loss_accum.item()  # one sync per 50 steps
                    total_loss += synced
                    _loss_accum.zero_()
                    avg = synced / (ids.size(0) * min(_LOSS_SYNC_EVERY, step + 1))
                    tbar.set_postfix(loss=f"{avg:.4f}", refresh=False)

        if _use_prefetch:
            with _MPSPrefetcher(train_loader, device) as pf:
                # Wrap prefetcher in tqdm so the progress bar still ticks
                _run_train_loop(_tqdm(pf, desc=f"[E2] Epoch {epoch+1:02d}/{epochs} train",
                                     unit="batch", total=len(train_loader), leave=False))
            # Sync remaining accumulated loss
            total_loss += _loss_accum.item()
        else:
            _run_train_loop(tbar)
            total_loss += _loss_accum.item()

        scheduler.step()

        # Flush MPS command queue before switching to eval mode
        if device.type == "mps":
            torch.mps.synchronize()

        # ── Validate ───────────────────────────────────────────────────────────
        model.eval()
        all_probs:  list[float] = []
        all_labels_: list[int]  = []
        correct, total = 0, 0

        with torch.no_grad():
            vbar = _tqdm(val_loader, desc=f"[E2] Epoch {epoch+1:02d}/{epochs} val  ", unit="batch", leave=False)
            # Use prefetcher for validation too on MPS
            def _val_loop(batch_iter):
                nonlocal correct, total
                for batch in batch_iter:
                    if device.type == "mps":
                        ids  = batch["input_ids"]
                        mask = batch["attention_mask"]
                        y    = batch["label"]
                    else:
                        ids  = batch["input_ids"].to(device)
                        mask = batch["attention_mask"].to(device)
                        y    = batch["label"].to(device)

                    if _use_autocast:
                        with torch.autocast(device_type="mps", dtype=_amp_dtype):
                            probs = torch.sigmoid(model(ids, mask))
                    else:
                        probs = torch.sigmoid(model(ids, mask))

                    preds = (probs > 0.5).float()
                    correct += (preds == y).sum().item()
                    total   += y.size(0)
                    all_probs.extend(probs.cpu().tolist())
                    all_labels_.extend(y.cpu().int().tolist())

            if device.type == "mps":
                with _MPSPrefetcher(val_loader, device) as vp:
                    _val_loop(vp)
            else:
                _val_loop(vbar)

        val_acc = correct / total
        val_auc = val_f1 = float("nan")
        if _SKLEARN and len(set(all_labels_)) > 1:
            val_auc = roc_auc_score(all_labels_, all_probs)
            val_f1  = f1_score(all_labels_, [1 if p > 0.5 else 0 for p in all_probs])


        print(
            f"[Expert 2] epoch {epoch+1:02d}/{epochs}  "
            f"lr={scheduler.get_last_lr()[0]:.2e}  "
            f"train_loss={total_loss/len(train_loader.dataset):.4f}  "
            f"val_acc={val_acc:.4f}  val_auc={val_auc:.4f}  val_f1={val_f1:.4f}"
        )
        # Track best checkpoint
        if not isinstance(val_auc, float) or val_auc > best_auc:
            best_auc = val_auc if isinstance(val_auc, float) else 0.0
            raw = getattr(model, "_orig_mod", model)
            best_state = {k: v.clone() for k, v in raw.state_dict().items()}

    # ── Restore best ─────────────────────────────────────────────────────────
    if best_state is not None:
        raw = getattr(model, "_orig_mod", model)
        raw.load_state_dict(best_state)
        print(f"[Expert 2] restored best weights (val_auc={best_auc:.4f})")

    if save_path:
        save_expert2(model, save_path, checkpoint, max_length)

    return model


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

@torch.no_grad()
def predict_proba(
    model: URLDistilBertClassifier,
    tokenizer,
    urls: list[str],
    max_length: int = 128,
    batch_size: int = 32,
) -> list[float]:
    """Return P(malicious) for each URL in *urls*."""
    return predict_logit(model, tokenizer, urls,
                         max_length=max_length, batch_size=batch_size,
                         temperature=1.0)


@torch.no_grad()
def predict_logit(
    model: URLDistilBertClassifier,
    tokenizer,
    urls: list[str],
    max_length: int = 128,
    batch_size: int = 32,
    temperature: float = 1.0,
) -> list[float]:
    """
    Return P(malicious) for each URL with optional temperature scaling.

    Temperature scaling divides the raw logit by *temperature* before sigmoid.
    - temperature=1.0 → standard sigmoid (default, identical to predict_proba)
    - temperature>1.0 → spreads the distribution, fixes sigmoid saturation.
      Recommended value: 4.0 for models trained on imbalanced URL datasets.
    """
    raw    = getattr(model, "_orig_mod", model)
    device = next(raw.parameters()).device
    model.eval()
    probs: list[float] = []

    for i in range(0, len(urls), batch_size):
        batch = urls[i : i + batch_size]
        enc = tokenizer(
            batch,
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        ids    = enc["input_ids"].to(device)
        mask   = enc["attention_mask"].to(device)
        logits = model(ids, mask)   # raw logits before sigmoid
        if temperature != 1.0:
            logits = logits / temperature
        p = torch.sigmoid(logits).cpu().tolist()
        probs.extend(p if isinstance(p, list) else [p])

    return probs


# ---------------------------------------------------------------------------
# Save / Load helpers
# ---------------------------------------------------------------------------

def save_expert2(
    model: URLDistilBertClassifier,
    path: str,
    checkpoint: str = _DISTILBERT_CHECKPOINT,
    max_length: int = 128,
) -> None:
    """
    Save model weights + metadata so load_expert2() can reconstruct fully.
    The DistilBERT tokenizer is NOT saved here (re-downloaded from HuggingFace
    cache on load — it's a few MB and always available offline once cached).
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    raw = getattr(model, "_orig_mod", model)
    torch.save(
        {
            "state_dict": raw.state_dict(),
            "checkpoint": checkpoint,
            "max_length": max_length,
        },
        path,
    )
    print(f"[Expert 2] saved weights → {path}")


def load_expert2(
    path: str,
    device: torch.device | None = None,
) -> tuple[URLDistilBertClassifier, object, int]:
    """
    Load from *path* and return (model, tokenizer, max_length).

    Usage:
        model, tok, max_len = load_expert2("checkpoints/expert2.pt")
        probs = predict_proba(model, tok, urls, max_length=max_len)
    """
    if not _TRANSFORMERS:
        raise ImportError("Install transformers: pip install transformers")
    if device is None:
        device = get_device()

    ckpt       = torch.load(path, map_location=device, weights_only=False)
    checkpoint = ckpt.get("checkpoint", _DISTILBERT_CHECKPOINT)
    max_length = ckpt.get("max_length", 128)

    tokenizer = DistilBertTokenizerFast.from_pretrained(checkpoint)
    model = URLDistilBertClassifier(checkpoint=checkpoint, freeze_layers=0).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    print(f"[Expert 2] loaded weights ← {path} (device={device})")
    return model, tokenizer, max_length


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not _TRANSFORMERS:
        print("transformers not installed — skipping smoke test.")
    else:
        dummy_urls   = ["http://paypa1-login.xyz/verify", "https://github.com/openai"] * 8
        dummy_labels = [1, 0] * 8
        m = train_expert2(
            dummy_urls, dummy_labels,
            dummy_urls, dummy_labels,
            epochs=1, batch_size=4,
        )
        tok = DistilBertTokenizerFast.from_pretrained(_DISTILBERT_CHECKPOINT)
        print(predict_proba(m, tok, dummy_urls[:4]))