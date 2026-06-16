"""
tree-sitter 기반 파싱 공용 유틸.

luaparser(순수 파이썬)의 파싱이 전체 난독화 시간의 ~90%를 차지하므로,
파싱이 무거운 패스들을 tree-sitter(C 파서, ~10x)로 옮긴다.

tree-sitter는 byte offset을, 파이프라인의 Replacement는 char offset을 쓰므로
TSContext가 byte→char 매핑을 들고 변환해 준다 (소스에 멀티바이트 문자가
있어도 안전).
"""
from __future__ import annotations

import tree_sitter as ts
import tree_sitter_lua as tsl

_LANG = ts.Language(tsl.language())
_PARSER = ts.Parser(_LANG)


def _build_b2c(script: str, nbytes: int) -> list[int]:
    """byte offset → char offset 매핑."""
    b2c = [0] * (nbytes + 1)
    b = 0
    for ci, ch in enumerate(script):
        nb = b + len(ch.encode("utf-8"))
        while b < nb:
            b2c[b] = ci
            b += 1
    b2c[nbytes] = len(script)
    return b2c


class TSContext:
    """파싱된 tree-sitter 트리 + byte/char 변환 + 순회 헬퍼.

    파이프라인이 base pass의 `tree` 인자로 전달한다.
    """

    def __init__(self, script: str):
        self.script = script
        data = script.encode("utf-8")
        self.tree = _PARSER.parse(data)
        self.root = self.tree.root_node
        self.b2c = _build_b2c(script, len(data))

    def cs(self, node) -> int:
        """char 기준 start."""
        return self.b2c[node.start_byte]

    def ce(self, node) -> int:
        """char 기준 inclusive end."""
        return self.b2c[node.end_byte] - 1

    def text(self, node) -> str:
        return self.script[self.b2c[node.start_byte]:self.b2c[node.end_byte]]

    def walk(self):
        """모든 노드를 DFS로 순회 (luaparser ast.walk 대체)."""
        stack = [self.root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    def first_child(self, node, typ):
        for c in node.children:
            if c.type == typ:
                return c
        return None


def parse(script: str) -> TSContext:
    return TSContext(script)
