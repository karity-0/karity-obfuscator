import random

from .base import BasePass, Replacement

MAX_INT = 0x7FFFFFFF


def _parse_int_token(token: str) -> int:
    """정수 리터럴 토큰을 값으로. (Python int(t,0)의 0o 8진수 함정 회피)"""
    t = token.lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)  # 선행 0 포함 10진수 그대로 (Lua 의미)


class NumberObfuscationPass(BasePass):
    parser = "treesitter"


    def _fmt_int(self, n: int) -> str:
        if random.random() < 0.5:
            return str(n)

        if n < 0:
            return f"-{hex(-n)}"

        return hex(n)

    def _gen_int_expr(self, value: int, depth: int) -> str:
        if depth <= 0:
            return self._fmt_int(value)

        op = random.choice(("xor", "add", "sub"))

        if op == "xor":
            # xor은 음수 처리 귀찮으니 제외
            if value < 0:
                return self._gen_int_expr(value, 0)

            a = random.randint(0, MAX_INT)
            b = a ^ value

            return (
                f"("
                f"{self._gen_int_expr(a, depth - 1)}"
                f" ~ "
                f"{self._gen_int_expr(b, depth - 1)}"
                f")"
            )

        if op == "add":
            a = random.randint(-1000000, 1000000)
            b = value - a

            return (
                f"("
                f"{self._gen_int_expr(a, depth - 1)}"
                f" + "
                f"{self._gen_int_expr(b, depth - 1)}"
                f")"
            )

        a = random.randint(-1000000, 1000000)
        b = a - value

        return (
            f"("
            f"{self._gen_int_expr(a, depth - 1)}"
            f" - "
            f"{self._gen_int_expr(b, depth - 1)}"
            f")"
        )

    def _is_float_literal(self, token: str) -> bool:
        token = token.lower()

        return (
            "." in token
            or "e" in token
        )

    def _make_float_expr(self, token: str) -> str:
        # float는 원본 토큰 유지
        # 141e2 -> ((0)+141e2)
        return (
            f"("
            f"{self._gen_int_expr(0, 1)}"
            f"+"
            f"({token})"
            f")"
        )

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in tree.walk():
            if node.type != "number":
                continue

            token = tree.text(node)

            if self._is_float_literal(token):
                expr = self._make_float_expr(token)
            else:
                expr = self._gen_int_expr(
                    _parse_int_token(token),
                    random.randint(1, 3),
                )

            replacements.append(
                Replacement(
                    start=tree.cs(node),
                    end=tree.ce(node),
                    new_text=expr,
                )
            )

        return replacements