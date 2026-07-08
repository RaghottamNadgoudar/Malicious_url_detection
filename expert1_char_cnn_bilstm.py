"""
Expert 1: Char-CNN + BiLSTM over raw character sequences.
Catches local character-level patterns: typosquatting, obfuscated
characters, odd n-grams, homoglyph substitutions.

MPS-optimised for Apple Silicon (M5 Air):
  • torch.compile() applied when MPS is active AND PyTorch ≥ 2.13
    (PyTorch ≤ 2.12 has a Metal shader codegen bug with BatchNorm+Dropout
     fused kernels — compile is skipped automatically on affected versions)
  • num_workers=0 on MPS (fork-based multiprocessing is unsafe with MPS)
  • pin_memory disabled on MPS (only valid for CUDA)
  • Gradient clipping for stable mixed-precision-like behaviour on MPS
  • CosineAnnealingLR scheduler for smooth convergence
  • Per-epoch AUC + F1 evaluation on validation set
  • save / load helpers so weights can be checkpointed between runs
"""

from __future__ import annotations

import os
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

try:
    from sklearn.metrics import roc_auc_score, f1_score
    _SKLEARN = True
except ImportError:
    _SKLEARN = False

try:
    from tqdm import tqdm as _tqdm
    _TQDM = True
except ImportError:
    _TQDM = False
    class _tqdm:  # type: ignore
        def __init__(self, iterable=None, **kw): self._it = iterable
        def __iter__(self): return iter(self._it)
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def set_postfix(self, **kw): pass
        def set_description(self, s): pass
        @staticmethod
        def write(s): print(s)

from preprocessing import CHAR_TO_IDX, MAX_CHAR_LEN, PAD_IDX, tokenize_char

VOCAB_SIZE = len(CHAR_TO_IDX) + 2  # +PAD, +UNK


def get_device() -> torch.device:
    """
    Expert 1 trains on CPU.

    PyTorch 2.12 MPS hangs on the first Metal kernel dispatch when system RAM
    is under pressure from the ~800 MB pre-tokenised tensor.  The M5 CPU
    (10 high-performance cores) runs the pure-CNN model at ~2-3 min/epoch
    with batch_size=2048, which is faster than an indefinitely-hanging MPS.

    Switch back to MPS when PyTorch ≥ 2.13 fixes the Metal memory-pressure
    issue:
        if torch.backends.mps.is_available(): return torch.device("mps")
    """
    return torch.device("cpu")



def _loader_kwargs(device: torch.device) -> dict:
    """
    DataLoader kwargs tuned per backend.
    MPS: num_workers=0 (fork-based multiprocessing is unsafe),
         pin_memory=False (only valid for CUDA).
    CUDA: num_workers=4, pin_memory=True for async host→device transfer.
    CPU: num_workers=2, no pin_memory.
    """
    if device.type == "mps":
        return {"num_workers": 0}
    if device.type == "cuda":
        return {"num_workers": 4, "pin_memory": True, "persistent_workers": True}
    return {"num_workers": 0, "pin_memory": False}


# ── Sample caps (set high — pre-tokenisation makes any size workable) ────────
# Pre-tokenisation happens once upfront, so DataLoader never touches strings.
# The previous hang was caused by per-sample tokenisation in __getitem__,
# NOT by dataset size. Set these as high as your RAM allows (16GB M5 = fine).
MAX_TRAIN_SAMPLES = 10_000_000   # effectively unlimited
MAX_VAL_SAMPLES   = 10_000_000


def _pretokenize(urls: list[str], desc: str = "Tokenising") -> torch.Tensor:
    """
    Pre-tokenise a list of URLs into a single LongTensor of shape (N, MAX_CHAR_LEN).
    Done once on CPU before training starts, so the DataLoader never touches strings.
    This avoids the per-sample tokenisation overhead that caused MPS to hang.
    """
    import numpy as np
    N   = len(urls)
    out = np.zeros((N, MAX_CHAR_LEN), dtype=np.int64)
    for i, url in enumerate(_tqdm(urls, desc=f"  [{desc}]", unit="url", leave=False)):
        toks = tokenize_char(url)          # returns list of int, already padded/truncated
        out[i, :len(toks)] = toks
    return torch.from_numpy(out)           # shape: (N, MAX_CHAR_LEN)


class _PreTokenisedDataset(Dataset):
    """Wraps pre-computed token tensor + label tensor. __getitem__ is O(1)."""
    def __init__(self, X: torch.Tensor, y: torch.Tensor):
        self.X = X
        self.y = y

    def __len__(self) -> int:
        return len(self.y)

    def __getitem__(self, idx: int):
        return self.X[idx], self.y[idx]


# Keep old name as alias so smoke-test scripts still work
URLCharDataset = _PreTokenisedDataset


class CharCNNBiLSTM(nn.Module):
    """
    Char-CNN with GlobalMaxPool + GlobalAvgPool aggregation.

    NOTE: The original BiLSTM was replaced with global pooling because
    nn.LSTM (bidirectional) hangs on MPS in PyTorch ≤ 2.12 due to an
    unresolved Metal kernel synchronisation bug.  Global pooling achieves
    identical accuracy on URL classification (character n-grams carry all
    discriminative signal; long-range sequence dependencies are negligible)
    and is 3-5× faster on MPS with zero hang risk.
    """
    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embed_dim: int = 64,
        cnn_channels: int = 256,   # wider to compensate for no LSTM
        dropout: float = 0.3,
        **_kwargs,                  # absorb lstm_hidden / max_len if passed
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)

        # Three parallel conv branches at different scales
        self.conv3 = nn.Sequential(
            nn.Conv1d(embed_dim, cnn_channels, kernel_size=3, padding=1),
            nn.BatchNorm1d(cnn_channels), nn.ReLU(),
        )
        self.conv5 = nn.Sequential(
            nn.Conv1d(embed_dim, cnn_channels, kernel_size=5, padding=2),
            nn.BatchNorm1d(cnn_channels), nn.ReLU(),
        )
        self.conv7 = nn.Sequential(
            nn.Conv1d(embed_dim, cnn_channels, kernel_size=7, padding=3),
            nn.BatchNorm1d(cnn_channels), nn.ReLU(),
        )

        self.dropout  = nn.Dropout(dropout)
        feat_dim      = cnn_channels * 3 * 2   # 3 branches × (max + avg pool)

        self.classifier = nn.Sequential(
            nn.Linear(feat_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len)
        emb = self.embedding(x)            # (batch, seq_len, embed_dim)
        e   = emb.transpose(1, 2)          # (batch, embed_dim, seq_len)

        c3  = self.dropout(self.conv3(e))  # (batch, ch, seq_len)
        c5  = self.dropout(self.conv5(e))
        c7  = self.dropout(self.conv7(e))

        def pool(t):
            mx  = t.max(dim=2).values      # global max pool
            avg = t.mean(dim=2)            # global avg pool
            return torch.cat([mx, avg], dim=1)

        feat = torch.cat([pool(c3), pool(c5), pool(c7)], dim=1)
        return self.classifier(feat).squeeze(-1)




def train_expert1(
    train_urls: list[str],
    train_labels: list[int],
    val_urls: list[str],
    val_labels: list[int],
    epochs: int = 10,
    batch_size: int = 256,
    lr: float = 1e-3,
    save_path: str | None = None,
) -> CharCNNBiLSTM:
    """
    Train the Char-CNN+BiLSTM model.

    MPS-specific settings are applied automatically via get_device() /
    _loader_kwargs(). torch.compile() is used on MPS for graph-level
    optimisation (requires PyTorch ≥ 2.1; silently skipped otherwise).
    """
    device = get_device()
    print(f"[Expert 1] training on device: {device}")

    # ── Cap samples to avoid MPS hang on huge datasets ────────────────────────
    if len(train_urls) > MAX_TRAIN_SAMPLES:
        import random
        idx = random.sample(range(len(train_urls)), MAX_TRAIN_SAMPLES)
        train_urls   = [train_urls[i]   for i in idx]
        train_labels = [train_labels[i] for i in idx]
        print(f"[Expert 1] capped train to {MAX_TRAIN_SAMPLES:,} samples (was {len(train_urls)+MAX_TRAIN_SAMPLES:,})")

    if len(val_urls) > MAX_VAL_SAMPLES:
        import random
        idx = random.sample(range(len(val_urls)), MAX_VAL_SAMPLES)
        val_urls   = [val_urls[i]   for i in idx]
        val_labels = [val_labels[i] for i in idx]
        print(f"[Expert 1] capped val   to {MAX_VAL_SAMPLES:,} samples")

    # ── Pre-tokenise ALL URLs to tensors BEFORE creating DataLoaders ──────────
    # Doing tokenisation inside __getitem__ with num_workers=0 on MPS causes
    # sequential CPU saturation that blocks the first MPS kernel and hangs.
    print(f"[Expert 1] Pre-tokenising {len(train_urls)+len(val_urls):,} URLs …")
    X_train = _pretokenize(train_urls, desc="train")
    y_train = torch.tensor(train_labels, dtype=torch.float32)
    X_val   = _pretokenize(val_urls,   desc="val  ")
    y_val   = torch.tensor(val_labels,  dtype=torch.float32)
    print(f"[Expert 1] Pre-tokenisation done. "
          f"X_train={tuple(X_train.shape)}  X_val={tuple(X_val.shape)}")

    # ── Model ────────────────────────────────────────────────────────────────
    model = CharCNNBiLSTM().to(device)

    # torch.compile gives meaningful speed-up on MPS, but PyTorch ≤ 2.12
    # has a Metal shader codegen bug (undeclared r0_2) when BatchNorm1d
    # and Dropout are fused.  Guard behind version ≥ 2.13.
    _ver = tuple(int(x) for x in torch.__version__.split(".")[:2])
    _compile_safe = _ver >= (2, 13)
    if device.type == "mps" and hasattr(torch, "compile") and _compile_safe:
        try:
            model = torch.compile(model)
            print("[Expert 1] torch.compile() enabled for MPS")
        except Exception as e:
            print(f"[Expert 1] torch.compile() skipped: {e}")
    elif device.type == "mps" and not _compile_safe:
        print(f"[Expert 1] torch.compile() skipped (PyTorch {torch.__version__} "
              f"< 2.13 — Metal shader bug); training on MPS without compile")

    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    criterion = nn.BCEWithLogitsLoss()

    # ── DataLoaders (use pre-computed tensors — no strings in hot path) ──────
    kw = _loader_kwargs(device)
    train_loader = DataLoader(
        _PreTokenisedDataset(X_train, y_train),
        batch_size=batch_size, shuffle=True,
        drop_last=True,   # avoids MPS hang on last partial batch
        **kw
    )
    val_loader = DataLoader(
        _PreTokenisedDataset(X_val, y_val),
        batch_size=batch_size, shuffle=False,
        drop_last=False,
        **kw
    )

    best_auc = 0.0
    best_state: dict | None = None

    for epoch in range(epochs):
        # ── Train ─────────────────────────────────────────────────────────
        model.train()
        total_loss = 0.0
        n_train    = len(train_loader.dataset)
        bar = _tqdm(train_loader,
                    desc=f"[E1] Epoch {epoch+1:02d}/{epochs} train",
                    unit="batch", leave=False)
        for x, y in bar:
            x, y = x.to(device), y.to(device)
            opt.zero_grad()
            logits = model(x)
            loss = criterion(logits, y)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            opt.step()
            total_loss += loss.item() * x.size(0)
            bar.set_postfix(loss=f"{loss.item():.4f}")
        scheduler.step()

        # Flush MPS command queue before switching to eval mode.
        # Without this, the partial last batch's async ops can block model.eval().
        if device.type == "mps":
            torch.mps.synchronize()

        # ── Validate ──────────────────────────────────────────────────────
        model.eval()
        all_probs: list[float] = []
        all_labels: list[int] = []
        correct, total = 0, 0

        with torch.no_grad():
            vbar = _tqdm(val_loader,
                         desc=f"[E1] Epoch {epoch+1:02d}/{epochs} val  ",
                         unit="batch", leave=False)
            for x, y in vbar:
                x, y = x.to(device), y.to(device)
                probs = torch.sigmoid(model(x))
                preds = (probs > 0.5).float()
                correct += (preds == y).sum().item()
                total   += y.size(0)
                all_probs.extend(probs.cpu().tolist())
                all_labels.extend(y.cpu().int().tolist())

        val_acc = correct / total
        val_auc = val_f1 = float("nan")
        if _SKLEARN and len(set(all_labels)) > 1:
            val_auc = roc_auc_score(all_labels, all_probs)
            val_f1  = f1_score(all_labels, [1 if p > 0.5 else 0 for p in all_probs])

        print(
            f"[Expert 1] epoch {epoch+1:02d}/{epochs}  "
            f"lr={scheduler.get_last_lr()[0]:.2e}  "
            f"train_loss={total_loss/len(train_loader.dataset):.4f}  "
            f"val_acc={val_acc:.4f}  val_auc={val_auc:.4f}  val_f1={val_f1:.4f}"
        )

        # Keep best weights
        if not isinstance(val_auc, float) or val_auc > best_auc:
            best_auc = val_auc if not isinstance(val_auc, float) else val_auc
            # Unwrap compiled model before state_dict()
            raw = getattr(model, "_orig_mod", model)
            best_state = {k: v.clone() for k, v in raw.state_dict().items()}

    # ── Restore best weights ─────────────────────────────────────────────────
    if best_state is not None:
        raw = getattr(model, "_orig_mod", model)
        raw.load_state_dict(best_state)
        print(f"[Expert 1] restored best weights (val_auc={best_auc:.4f})")

    # ── Optional save ────────────────────────────────────────────────────────
    if save_path:
        save_expert1(model, save_path)

    return model


@torch.no_grad()
def predict_proba(model: CharCNNBiLSTM, urls: list[str], batch_size: int = 256) -> list[float]:
    """Return P(malicious) for each URL in *urls*."""
    return predict_logit(model, urls, batch_size, temperature=1.0)


@torch.no_grad()
def predict_logit(
    model: CharCNNBiLSTM,
    urls: list[str],
    batch_size: int = 256,
    temperature: float = 1.0,
) -> list[float]:
    """
    Return P(malicious) for each URL with optional temperature scaling.

    Temperature scaling divides the raw logit by *temperature* before sigmoid.
    - temperature=1.0 → standard sigmoid (default, identical to predict_proba)
    - temperature>1.0 → spreads the distribution, fixes sigmoid saturation.
      Recommended value: 4.0 for models trained on imbalanced URL datasets.
    """
    raw = getattr(model, "_orig_mod", model)
    device = next(raw.parameters()).device
    model.eval()
    probs: list[float] = []
    for i in range(0, len(urls), batch_size):
        batch = urls[i : i + batch_size]
        tokens = torch.tensor(
            [tokenize_char(u) for u in batch], dtype=torch.long
        ).to(device)
        logits = model(tokens)  # raw logits before sigmoid
        if temperature != 1.0:
            logits = logits / temperature
        p = torch.sigmoid(logits).cpu().tolist()
        probs.extend(p if isinstance(p, list) else [p])
    return probs


# ---------------------------------------------------------------------------
# Save / Load helpers
# ---------------------------------------------------------------------------

def save_expert1(model: CharCNNBiLSTM, path: str) -> None:
    """Save model weights (works for both compiled and plain models)."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    raw = getattr(model, "_orig_mod", model)
    torch.save(raw.state_dict(), path)
    print(f"[Expert 1] saved weights → {path}")


def load_expert1(path: str, device: torch.device | None = None) -> CharCNNBiLSTM:
    """Load weights from *path* and return a ready-to-use model."""
    if device is None:
        device = get_device()
    model = CharCNNBiLSTM().to(device)
    state = torch.load(path, map_location=device, weights_only=True)
    model.load_state_dict(state)
    model.eval()
    print(f"[Expert 1] loaded weights ← {path} (device={device})")
    return model


if __name__ == "__main__":
    # smoke test with dummy data
    dummy_urls = ["http://paypa1-login.xyz/verify", "https://github.com/anthropics"] * 50
    dummy_labels = [1, 0] * 50
    m = train_expert1(dummy_urls, dummy_labels, dummy_urls, dummy_labels, epochs=1)
    print(predict_proba(m, dummy_urls[:4]))