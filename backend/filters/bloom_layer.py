"""
Stage 1 — Bloom Filter Layer
Implements three Bloom Filter variants from scratch:
  1. Counting Bloom Filter   — supports deletions (bit → counter)
  2. Scalable Bloom Filter   — auto-grows with new filter slices
  3. Cuckoo Filter           — fingerprint-based, ~2× lower FP rate

Hash families: MurmurHash3 (via mmh3) + FNV-1a (pure-python fallback)
DAA mapping: Hashing, probabilistic data structures, optimal k formula
"""

import math
import struct
from typing import List, Optional
from array import array

# ── Try mmh3 (MurmurHash3), fall back to FNV-1a + DJB2 ──────────────────────
try:
    import mmh3 as _mmh3
    def _murmurhash(key: str, seed: int) -> int:
        return _mmh3.hash(key, seed, signed=False)
except ImportError:
    def _murmurhash(key: str, seed: int) -> int:
        """Pure-Python Murmur3-inspired 32-bit hash."""
        h = seed ^ (len(key) * 0xc4ceb9fe)
        for ch in key.encode():
            h ^= ch
            h = (h * 0x517cc1b727220a95) & 0xFFFFFFFF
            h ^= h >> 16
        return h


def _fnv1a(key: str) -> int:
    """FNV-1a 32-bit hash — second independent hash family."""
    h = 2166136261
    for byte in key.encode():
        h ^= byte
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _double_hash(key: str, i: int, m: int) -> int:
    """
    Double hashing: h(k,i) = (h1(k) + i*h2(k)) mod m
    Gives k independent hash positions from 2 hash families.
    """
    h1 = _murmurhash(key, seed=0)
    h2 = _fnv1a(key)
    if h2 % m == 0:          # h2 must be coprime with m
        h2 = 1
    return (h1 + i * h2) % m


def _optimal_k(m: int, n: int) -> int:
    """Optimal number of hash functions: k = (m/n) × ln2"""
    if n == 0:
        return 1
    k = int(round((m / n) * math.log(2)))
    return max(1, min(k, 20))


# ─────────────────────────────────────────────────────────────────────────────
# 1. Counting Bloom Filter
# ─────────────────────────────────────────────────────────────────────────────

class CountingBloomFilter:
    """
    Bloom Filter where each cell is a counter (4-bit saturating).
    Supports both insertion AND deletion (unlike standard BF).

    Parameters
    ----------
    capacity : int   expected number of elements
    fp_rate  : float desired false-positive rate (e.g. 0.01)
    """

    def __init__(self, capacity: int = 100_000, fp_rate: float = 0.01):
        self.capacity = capacity
        self.fp_rate = fp_rate
        # Optimal bit-array size: m = -n*ln(p) / (ln2)^2
        self.m = max(1, int(-capacity * math.log(fp_rate) / (math.log(2) ** 2)))
        self.k = _optimal_k(self.m, capacity)
        # Use unsigned byte array (counters 0-255, clamped at 255)
        self._counters: array = array('B', [0] * self.m)
        self._count = 0

    def add(self, key: str) -> None:
        for i in range(self.k):
            idx = _double_hash(key, i, self.m)
            if self._counters[idx] < 255:
                self._counters[idx] += 1
        self._count += 1

    def remove(self, key: str) -> bool:
        """Remove key. Returns False if key was not present."""
        if not self.contains(key):
            return False
        for i in range(self.k):
            idx = _double_hash(key, i, self.m)
            if self._counters[idx] > 0:
                self._counters[idx] -= 1
        self._count -= 1
        return True

    def contains(self, key: str) -> bool:
        """Returns True if key is (probably) in the set."""
        return all(
            self._counters[_double_hash(key, i, self.m)] > 0
            for i in range(self.k)
        )

    @property
    def load_factor(self) -> float:
        """Fraction of counter slots that are non-zero."""
        non_zero = sum(1 for c in self._counters if c > 0)
        return non_zero / self.m

    def __repr__(self):
        return (f"CountingBloomFilter(m={self.m}, k={self.k}, "
                f"n={self._count}, load={self.load_factor:.2%})")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Scalable Bloom Filter
# ─────────────────────────────────────────────────────────────────────────────

class _BloomSlice:
    """Single slice of a Scalable Bloom Filter (standard bit-array BF)."""

    def __init__(self, capacity: int, fp_rate: float):
        self.m = max(1, int(-capacity * math.log(fp_rate) / (math.log(2) ** 2)))
        self.k = _optimal_k(self.m, capacity)
        # Bit array stored as int array of 64-bit words
        self._words: array = array('Q', [0] * ((self.m + 63) // 64))

    def _set(self, idx: int) -> None:
        self._words[idx >> 6] |= (1 << (idx & 63))

    def _get(self, idx: int) -> bool:
        return bool(self._words[idx >> 6] & (1 << (idx & 63)))

    def add(self, key: str) -> None:
        for i in range(self.k):
            self._set(_double_hash(key, i, self.m))

    def contains(self, key: str) -> bool:
        return all(self._get(_double_hash(key, i, self.m)) for i in range(self.k))

    @property
    def fill_ratio(self) -> float:
        bits_set = sum(bin(w).count('1') for w in self._words)
        return bits_set / self.m


class ScalableBloomFilter:
    """
    Starts with one bloom slice; when fill ratio exceeds threshold,
    adds a new slice with tighter FP rate (r × previous rate).

    Parameters
    ----------
    initial_capacity : int   initial slice capacity
    fp_rate          : float initial false-positive rate
    r                : float FP rate tightening ratio per slice (0 < r < 1)
    fill_threshold   : float fill ratio at which a new slice is added
    """

    def __init__(
        self,
        initial_capacity: int = 50_000,
        fp_rate: float = 0.01,
        r: float = 0.8,
        fill_threshold: float = 0.6,
    ):
        self.fp_rate = fp_rate
        self.r = r
        self.fill_threshold = fill_threshold
        self._slices: List[_BloomSlice] = [_BloomSlice(initial_capacity, fp_rate)]
        self._current_fp = fp_rate
        self._initial_capacity = initial_capacity
        self._count = 0

    def _maybe_grow(self) -> None:
        if self._slices[-1].fill_ratio >= self.fill_threshold:
            self._current_fp *= self.r
            self._slices.append(
                _BloomSlice(self._initial_capacity, self._current_fp)
            )

    def add(self, key: str) -> None:
        self._maybe_grow()
        self._slices[-1].add(key)
        self._count += 1

    def contains(self, key: str) -> bool:
        return any(s.contains(key) for s in self._slices)

    @property
    def num_slices(self) -> int:
        return len(self._slices)

    def __repr__(self):
        return (f"ScalableBloomFilter(slices={self.num_slices}, "
                f"n={self._count}, current_fp={self._current_fp:.6f})")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Cuckoo Filter
# ─────────────────────────────────────────────────────────────────────────────

_EMPTY = 0
_FINGERPRINT_BITS = 8
_FINGERPRINT_MASK = (1 << _FINGERPRINT_BITS) - 1   # 0xFF
_MAX_KICKS = 500


class CuckooFilter:
    """
    Cuckoo Filter: two-choice hashing with fingerprints.
    Lower false-positive rate than standard BF at same space,
    and supports deletion natively.

    Two buckets per item, each bucket holds `bucket_size` fingerprints.
    Eviction (cuckoo kicking) resolves collisions.

    DAA: Two-choice hashing, amortized O(1) insert/lookup/delete.
    """

    def __init__(self, capacity: int = 100_000, bucket_size: int = 4):
        # Number of buckets: next power of 2 ≥ capacity / bucket_size
        raw = max(1, capacity // bucket_size)
        self.num_buckets = 1 << (raw - 1).bit_length()  # next power of 2
        self.bucket_size = bucket_size
        # Each bucket: list of `bucket_size` fingerprint slots (0 = empty)
        self._table: List[List[int]] = [
            [_EMPTY] * bucket_size for _ in range(self.num_buckets)
        ]
        self._count = 0

    # ── Fingerprint & index helpers ────────────────────────────────────────

    @staticmethod
    def _fingerprint(key: str) -> int:
        fp = _murmurhash(key, seed=42) & _FINGERPRINT_MASK
        return fp if fp != _EMPTY else 1   # 0 is reserved for empty

    def _index1(self, key: str) -> int:
        return _murmurhash(key, seed=0) % self.num_buckets

    def _index2(self, i1: int, fp: int) -> int:
        """Alternate index — XOR with hash of fingerprint (reversible)."""
        return (i1 ^ _murmurhash(str(fp), seed=7)) % self.num_buckets

    # ── Bucket operations ──────────────────────────────────────────────────

    def _bucket_insert(self, idx: int, fp: int) -> bool:
        bucket = self._table[idx]
        for j in range(self.bucket_size):
            if bucket[j] == _EMPTY:
                bucket[j] = fp
                return True
        return False

    def _bucket_contains(self, idx: int, fp: int) -> bool:
        return fp in self._table[idx]

    def _bucket_remove(self, idx: int, fp: int) -> bool:
        bucket = self._table[idx]
        for j in range(self.bucket_size):
            if bucket[j] == fp:
                bucket[j] = _EMPTY
                return True
        return False

    # ── Public API ─────────────────────────────────────────────────────────

    def add(self, key: str) -> bool:
        """
        Insert key. Returns True on success, False if filter is full
        (cycle detected after MAX_KICKS evictions).
        """
        import random
        fp = self._fingerprint(key)
        i1 = self._index1(key)
        i2 = self._index2(i1, fp)

        if self._bucket_insert(i1, fp) or self._bucket_insert(i2, fp):
            self._count += 1
            return True

        # Cuckoo kicking
        i = random.choice([i1, i2])
        for _ in range(_MAX_KICKS):
            # Evict a random fingerprint from bucket i
            j = random.randrange(self.bucket_size)
            fp, self._table[i][j] = self._table[i][j], fp
            i = self._index2(i, fp)
            if self._bucket_insert(i, fp):
                self._count += 1
                return True

        # Filter too full
        return False

    def contains(self, key: str) -> bool:
        fp = self._fingerprint(key)
        i1 = self._index1(key)
        i2 = self._index2(i1, fp)
        return self._bucket_contains(i1, fp) or self._bucket_contains(i2, fp)

    def remove(self, key: str) -> bool:
        fp = self._fingerprint(key)
        i1 = self._index1(key)
        i2 = self._index2(i1, fp)
        if self._bucket_remove(i1, fp) or self._bucket_remove(i2, fp):
            self._count -= 1
            return True
        return False

    @property
    def load_factor(self) -> float:
        used = sum(1 for b in self._table for fp in b if fp != _EMPTY)
        return used / (self.num_buckets * self.bucket_size)

    def __repr__(self):
        return (f"CuckooFilter(buckets={self.num_buckets}, "
                f"bucket_size={self.bucket_size}, "
                f"n={self._count}, load={self.load_factor:.2%})")
