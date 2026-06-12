import random

from luaparser import astnodes

from .base import BasePass, Replacement

MAX_INT = 0x7FFFFFFF


class NumberObfuscationPass(BasePass):

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

        for node in self.walk(tree):
            if not isinstance(node, astnodes.Number):
                continue

            token = node._first_token.text

            if self._is_float_literal(token):
                expr = self._make_float_expr(token)
            else:
                expr = self._gen_int_expr(
                    int(node.n),
                    random.randint(2, 3),
                )

            replacements.append(
                Replacement(
                    start=node.start_char,
                    end=node.stop_char,
                    new_text=expr,
                )
            )

        return replacements