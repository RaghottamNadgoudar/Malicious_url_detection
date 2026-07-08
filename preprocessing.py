"""
preprocessing.py
Shared tokenization & vocabulary for Expert 1 (Char-CNN-BiLSTM).
Keeps constants in one place so all experts import consistently.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Character vocabulary
# ---------------------------------------------------------------------------

# Printable ASCII 32-126, plus a few extras common in URLs
_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ".-_~:/?#[]@!$&'()*+,;=%"
)

# Index 0 → PAD,  Index 1 → UNK,  indices 2+ → actual chars
PAD_IDX = 0
UNK_IDX = 1
CHAR_TO_IDX: dict[str, int] = {ch: i + 2 for i, ch in enumerate(_CHARS)}

MAX_CHAR_LEN = 200  # truncate / pad to this length


def tokenize_char(url: str, max_len: int = MAX_CHAR_LEN) -> list[int]:
    """
    Convert a URL string to a fixed-length integer token list.
    - Characters not in the vocabulary → UNK_IDX (1)
    - Sequences shorter than max_len are right-padded with PAD_IDX (0)
    - Sequences longer than max_len are truncated on the right
    """
    tokens = [CHAR_TO_IDX.get(ch, UNK_IDX) for ch in url[:max_len]]
    # Pad if necessary
    tokens += [PAD_IDX] * (max_len - len(tokens))
    return tokens
