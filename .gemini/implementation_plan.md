# MPS Training Optimisation Plan

## Bottlenecks identified

| Problem | Root cause | Fix |
|---|---|---|
| 1.73 batch/s (slow) | MPS Metal shader warmup + no bf16 | autocast bfloat16 |
| num_workers=0 | MPS fork-safety | background thread prefetcher |
| loss.item() every step | CPU↔GPU sync stall | batch the sync every N steps |
| No fused optimizer | Kernel launch overhead | foreach=True AdamW |
| torch.compile skipped | PyTorch 2.12 bug guard | try reduce-overhead mode |
| tqdm.set_postfix every step | Python object overhead | throttle to every 50 steps |
