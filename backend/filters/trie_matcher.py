"""
Stage 1 — Patricia Trie / Radix Tree for Domain Prefix Matching
Used to detect:
  - Known malicious domain prefixes  (e.g. "secure-paypal.", "login-verify.")
  - Known safe TLD+domain suffixes   (e.g. "github.com", "google.com")
  - Subdomain abuse patterns         (e.g. "*.paypal.com.evil.xyz")

Algorithm: Patricia Trie (compressed Radix-2 Trie) with recursive DFS traversal.

DAA Mapping
-----------
  Unit-II  : Decrease & Conquer — tree reduction, DFS on trie nodes
  Unit-III : Transform & Conquer — problem → trie structure → O(|key|) queries
  Complexity: Insert O(|key|), Search O(|key|), Space O(ΣΣΣΣ) compressed
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse


# ── Trie Node ─────────────────────────────────────────────────────────────────

@dataclass
class TrieNode:
    """
    A node in the Patricia (compressed) Trie.
    Each edge is labelled with a string (compressed common prefix),
    reducing tree height from O(|key|) to O(number of branches).
    """
    label: str = ""                          # edge label (compressed prefix)
    children: Dict[str, "TrieNode"] = field(default_factory=dict)
    is_terminal: bool = False                # True if this node ends a key
    payload: Optional[str] = None           # metadata (e.g. "malicious", "safe")

    def __repr__(self):
        return (f"TrieNode(label={self.label!r}, "
                f"terminal={self.is_terminal}, "
                f"children={list(self.children.keys())})")


# ── Patricia Trie ─────────────────────────────────────────────────────────────

class PatriciaTrie:
    """
    Compressed Radix Trie (Patricia Trie) for string prefix matching.

    Features
    --------
    - Insert a key with optional payload
    - Exact match (contains)
    - Prefix match: does any stored key match a prefix of the query?
    - Suffix match: does the query match a suffix/subdomain of any stored key?
    - DFS traversal: yields all stored (key, payload) pairs
    - Delete a key

    Space: O(unique characters across all keys) — compressed edges save space.
    """

    def __init__(self):
        self._root = TrieNode(label="")
        self._size = 0

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _common_prefix_len(a: str, b: str) -> int:
        """Length of the longest common prefix of a and b."""
        i = 0
        min_len = min(len(a), len(b))
        while i < min_len and a[i] == b[i]:
            i += 1
        return i

    # ── Insert ────────────────────────────────────────────────────────────────

    def insert(self, key: str, payload: Optional[str] = None) -> None:
        """
        Insert `key` into the Patricia Trie.

        Steps (Decrease & Conquer):
        1. Start at root, traverse matching edges.
        2. If edge label matches key prefix → recurse deeper.
        3. If partial match → split edge (create new internal node).
        4. If no match → create new child edge.
        """
        self._insert_node(self._root, key, payload)
        self._size += 1

    def _insert_node(self, node: TrieNode, key: str, payload: Optional[str]) -> None:
        if not key:
            node.is_terminal = True
            node.payload = payload
            return

        first_char = key[0]

        if first_char not in node.children:
            # No edge for this character → create new leaf
            new_node = TrieNode(label=key, is_terminal=True, payload=payload)
            node.children[first_char] = new_node
            return

        child = node.children[first_char]
        cp_len = self._common_prefix_len(key, child.label)

        if cp_len == len(child.label):
            # Edge label is a prefix of key → recurse with remaining key
            self._insert_node(child, key[cp_len:], payload)
        else:
            # Partial match → split the edge
            #
            # Before: node --[child.label]--> child
            # After:  node --[common]--> split_node --[child.label[cp_len:]]--> child
            #                                        --[key[cp_len:]]--> new_leaf
            #
            split_label = child.label[:cp_len]
            old_suffix  = child.label[cp_len:]

            # Relocate child under new split node
            child.label = old_suffix
            split_node = TrieNode(label=split_label)
            split_node.children[old_suffix[0]] = child

            # Remaining key after common prefix
            remaining = key[cp_len:]
            if remaining:
                leaf = TrieNode(label=remaining, is_terminal=True, payload=payload)
                split_node.children[remaining[0]] = leaf
            else:
                split_node.is_terminal = True
                split_node.payload = payload

            node.children[first_char] = split_node

    # ── Search ────────────────────────────────────────────────────────────────

    def contains(self, key: str) -> Tuple[bool, Optional[str]]:
        """Exact key lookup. Returns (found, payload)."""
        node = self._search_node(self._root, key)
        if node and node.is_terminal:
            return True, node.payload
        return False, None

    def _search_node(self, node: TrieNode, key: str) -> Optional[TrieNode]:
        """Traverse trie following compressed edges. Returns terminal node or None."""
        if not key:
            return node

        first_char = key[0]
        if first_char not in node.children:
            return None

        child = node.children[first_char]
        cp_len = self._common_prefix_len(key, child.label)

        if cp_len < len(child.label):
            return None                   # partial edge match → not found
        return self._search_node(child, key[cp_len:])

    def has_prefix_of(self, query: str) -> Tuple[bool, Optional[str]]:
        """
        Prefix match: is any stored key a prefix of `query`?
        Used to detect: stored "secure-paypal." matches "secure-paypal.evil.xyz"
        """
        return self._prefix_search(self._root, query)

    def _prefix_search(
        self, node: TrieNode, remaining: str
    ) -> Tuple[bool, Optional[str]]:
        if node.is_terminal:
            return True, node.payload           # stored key is prefix of query

        if not remaining:
            return False, None

        first_char = remaining[0]
        if first_char not in node.children:
            return False, None

        child = node.children[first_char]
        cp_len = self._common_prefix_len(remaining, child.label)

        if cp_len < len(child.label):
            # Partial edge — child label extends beyond remaining query
            # → remaining is a prefix of child.label → no stored key is prefix
            return False, None

        return self._prefix_search(child, remaining[cp_len:])

    # ── DFS Traversal ─────────────────────────────────────────────────────────

    def all_keys(self) -> Iterator[Tuple[str, Optional[str]]]:
        """
        DFS traversal — yields all (key, payload) pairs in lexicographic order.
        DAA: Classic Decrease & Conquer DFS on tree structure.
        """
        yield from self._dfs(self._root, prefix="")

    def _dfs(self, node: TrieNode, prefix: str) -> Iterator[Tuple[str, Optional[str]]]:
        current = prefix + node.label
        if node.is_terminal:
            yield current, node.payload
        for child in sorted(node.children.values(), key=lambda n: n.label):
            yield from self._dfs(child, current)

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete(self, key: str) -> bool:
        """Remove a key from the trie. Returns True if key was found."""
        deleted, _ = self._delete_node(self._root, key)
        if deleted:
            self._size -= 1
        return deleted

    def _delete_node(
        self, node: TrieNode, key: str
    ) -> Tuple[bool, bool]:
        """
        Returns (deleted: bool, node_can_be_removed: bool).
        Node can be removed if it has no children and is not terminal.
        """
        if not key:
            if not node.is_terminal:
                return False, False
            node.is_terminal = False
            node.payload = None
            return True, not node.children

        first_char = key[0]
        if first_char not in node.children:
            return False, False

        child = node.children[first_char]
        cp_len = self._common_prefix_len(key, child.label)
        if cp_len < len(child.label):
            return False, False

        deleted, remove_child = self._delete_node(child, key[cp_len:])
        if remove_child:
            del node.children[first_char]
        elif deleted and not child.children:
            # Merge with single remaining child if possible
            del node.children[first_char]

        can_remove = not node.is_terminal and not node.children
        return deleted, can_remove

    def __len__(self) -> int:
        return self._size

    def __repr__(self):
        return f"PatriciaTrie(size={self._size})"


# ── Domain Matcher (wraps two tries) ─────────────────────────────────────────

class DomainTrieMatcher:
    """
    Dual-trie domain matcher:
      _malicious_trie : prefixes/domains known malicious
      _safe_trie      : whitelisted domains (exact + parent-domain)

    Query logic
    -----------
    1. Exact match in safe_trie → SAFE
    2. Parent domain match in safe_trie → SAFE
    3. Exact match in malicious_trie → MALICIOUS
    4. Prefix match in malicious_trie → MALICIOUS (subdomain abuse)
    5. No match → UNKNOWN (pass to bloom/ML layers)
    """

    def __init__(self):
        self._malicious = PatriciaTrie()
        self._safe      = PatriciaTrie()

    def add_malicious_domain(self, domain: str) -> None:
        self._malicious.insert(domain.lower().strip(), payload="malicious")

    def add_safe_domain(self, domain: str) -> None:
        self._safe.insert(domain.lower().strip(), payload="safe")

    def query(self, url: str) -> str:
        """Returns 'safe', 'malicious', or 'unknown'."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(":")[0].lstrip("www.")
        except Exception:
            return "unknown"

        # 1. Exact safe match
        found, _ = self._safe.contains(domain)
        if found:
            return "safe"

        # 2. Parent-domain safe match (e.g. "github.com" covers "api.github.com")
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            found, _ = self._safe.contains(parent)
            if found:
                return "safe"

        # 3. Exact malicious match
        found, _ = self._malicious.contains(domain)
        if found:
            return "malicious"

        # 4. Prefix malicious match (detects subdomain abuse)
        found, _ = self._malicious.has_prefix_of(domain)
        if found:
            return "malicious"

        return "unknown"

    def bulk_load_malicious(self, domains: List[str]) -> int:
        count = 0
        for d in domains:
            d = d.strip().lower()
            if d:
                self.add_malicious_domain(d)
                count += 1
        return count

    def bulk_load_safe(self, domains: List[str]) -> int:
        count = 0
        for d in domains:
            d = d.strip().lower()
            if d:
                self.add_safe_domain(d)
                count += 1
        return count

    def stats(self) -> Dict:
        return {
            "malicious_domains": len(self._malicious),
            "safe_domains": len(self._safe),
        }

    def __repr__(self):
        return (f"DomainTrieMatcher(malicious={len(self._malicious)}, "
                f"safe={len(self._safe)})")


# Fix missing import
from typing import Dict

# ── Module-level singleton ────────────────────────────────────────────────────
domain_trie_matcher = DomainTrieMatcher()
