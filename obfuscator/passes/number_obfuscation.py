import math
import random

from .base import BasePass, Replacement


MAX_INT = 0x7FFFFFFF
MAX_FLOAT_BACKED_INT = (1 << 39) - 1

FLOAT_INT_CHANCE = 0.40
FLOAT_CHAIN_MIN = 5
FLOAT_CHAIN_MAX = 8

QUANT_BITS = 12
QUANT = 1 << QUANT_BITS


def _parse_int_token(token: str) -> int:
    t = token.strip().lower()

    if t.startswith("0x"):
        return int(t, 16)

    return int(t, 10)


def _parse_float_token(token: str) -> float:
    t = token.strip().lower()

    if t.startswith("0x"):
        if "p" not in t:
            t += "p0"

        return float.fromhex(t)

    return float(t)


class NumberObfuscationPass(BasePass):
    parser = "treesitter"

    @staticmethod
    def _inside_string_char(node, tree) -> bool:
        current = node.parent
        while current is not None:
            if current.type == "function_call":
                return bool(
                    current.children
                    and tree.text(current.children[0]) == "string.char"
                )
            if current.type in ("assignment_statement", "return_statement"):
                return False
            current = current.parent
        return False

    def _random_hex_case(self, text: str) -> str:
        out = []

        for ch in text:
            if ch in "abcdefABCDEF":
                ch = ch.upper() if random.getrandbits(1) else ch.lower()
            elif ch in "xX":
                ch = "X" if random.getrandbits(1) else "x"
            elif ch in "pP":
                ch = "P" if random.getrandbits(1) else "p"

            out.append(ch)

        return "".join(out)

    def _random_exp_case(self, text: str) -> str:
        out = []

        for ch in text:
            if ch in "eE":
                out.append(
                    "E" if random.getrandbits(1) else "e"
                )
            else:
                out.append(ch)

        return "".join(out)

    def _fmt_plain_int(self, value: int) -> str:
        if random.getrandbits(1):
            return str(value)

        if value < 0:
            text = "-" + hex(-value)
        else:
            text = hex(value)

        return self._random_hex_case(text)

    def _compact_scientific(self, value: float) -> str:
        text = repr(value)

        if "e" in text.lower():
            mantissa, exponent = text.lower().split("e")
            exp = int(exponent)

            if random.getrandbits(1):
                result = f"{mantissa}e{exp}"
            else:
                result = f"{mantissa}e{exp:+d}"

            return self._random_exp_case(result)

        sign = ""

        if text.startswith("-"):
            sign = "-"
            text = text[1:]

        if "." in text:
            whole, frac = text.split(".", 1)
        else:
            whole, frac = text, ""

        if whole.strip("0"):
            first = 0

            while (
                first < len(whole)
                and whole[first] == "0"
            ):
                first += 1

            significant = (
                whole[first:] + frac
            )

            exp = (
                len(whole)
                - first
                - 1
            )

        else:
            first = 0

            while (
                first < len(frac)
                and frac[first] == "0"
            ):
                first += 1

            if first >= len(frac):
                return random.choice(
                    (
                        "0e0",
                        "0E+0",
                        ".0e0",
                    )
                )

            significant = frac[first:]
            exp = -(first + 1)

        significant = significant.rstrip("0")

        if not significant:
            significant = "0"

        if len(significant) == 1:
            mantissa = significant
        else:
            mantissa = (
                significant[0]
                + "."
                + significant[1:]
            )

        if random.getrandbits(1):
            result = (
                f"{sign}{mantissa}e{exp}"
            )
        else:
            result = (
                f"{sign}{mantissa}"
                f"e{exp:+d}"
            )

        return self._random_exp_case(result)

    def _shift_decimal_fraction(
        self,
        value: float,
    ) -> str | None:
        scientific = self._compact_scientific(
            value
        )

        lower = scientific.lower()

        if "e" not in lower:
            return None

        mantissa, exponent = lower.split("e")
        exp = int(exponent)

        sign = ""

        if mantissa.startswith("-"):
            sign = "-"
            mantissa = mantissa[1:]

        digits = mantissa.replace(".", "")

        if not digits:
            return None

        result = (
            f"{sign}.{digits}"
            f"e{exp + 1:+d}"
        )

        return self._random_exp_case(result)

    def _fmt_hex_fixed(
        self,
        value: float,
    ) -> str | None:
        scaled = value * QUANT
        rounded = round(scaled)

        if scaled != rounded:
            return None

        q = int(rounded)
        sign = ""

        if q < 0:
            sign = "-"
            q = -q

        whole, frac = divmod(
            q,
            QUANT,
        )

        frac_hex = (
            f"{frac:03x}"
            .rstrip("0")
        )

        if not frac_hex:
            frac_hex = "0"

        if whole == 0:
            if random.getrandbits(1):
                text = (
                    f"{sign}0x."
                    f"{frac_hex}"
                )
            else:
                text = (
                    f"{sign}0x0."
                    f"{frac_hex}"
                )
        else:
            text = (
                f"{sign}0x{whole:x}."
                f"{frac_hex}"
            )

        return self._random_hex_case(
            text
        )

    def _trim_hex_float(
        self,
        text: str,
    ) -> str:
        t = text.lower()
        sign = ""

        if t.startswith("-"):
            sign = "-"
            t = t[1:]

        mantissa, exponent = t.split(
            "p",
            1,
        )

        head, frac = mantissa.split(
            ".",
            1,
        )

        frac = frac.rstrip("0")

        if frac:
            mantissa = (
                f"{head}.{frac}"
            )
        elif random.random() < 0.35:
            mantissa = head
        else:
            mantissa = (
                f"{head}.0"
            )

        return self._random_hex_case(
            sign
            + mantissa
            + "p"
            + exponent
        )

    def _shift_hex_fraction(
        self,
        value: float,
        hex_text: str | None = None,
    ) -> str | None:
        if hex_text is None:
            hex_text = value.hex()

        text = hex_text.lower()
        sign = ""

        if text.startswith("-"):
            sign = "-"
            text = text[1:]

        mantissa, exponent = text.split(
            "p",
            1,
        )

        exp = int(exponent)

        body = mantissa[2:]

        if "." not in body:
            return None

        whole, frac = body.split(
            ".",
            1,
        )

        digits = (
            whole + frac
        ).rstrip("0")

        if not digits:
            return "0x.0p0"

        result = (
            f"{sign}0x.{digits}"
            f"p{exp + len(whole) * 4:+d}"
        )

        return self._random_hex_case(
            result
        )

    def _fmt_decimal_short(
        self,
        value: float,
    ) -> str:
        text = repr(value)

        if len(text) > 16:
            return self._fmt_hex_float(
                value
            )

        if (
            "." not in text
            and "e" not in text.lower()
        ):
            text += ".0"

        return self._random_exp_case(
            text
        )

    def _fmt_decimal_scientific(
        self,
        value: float,
    ) -> str:
        if random.random() < 0.40:
            shifted = (
                self._shift_decimal_fraction(
                    value
                )
            )

            if shifted is not None:
                return shifted

        return self._compact_scientific(
            value
        )

    def _fmt_hex_float(
        self,
        value: float,
    ) -> str:
        hex_text = value.hex()

        if random.random() < 0.45:
            shifted = (
                self._shift_hex_fraction(
                    value,
                    hex_text,
                )
            )

            if shifted is not None:
                return shifted

        return self._trim_hex_float(
            hex_text
        )

    def _fmt_float_style(
        self,
        value: float,
        style: str,
    ) -> str:
        if style == "hex_fixed":
            result = self._fmt_hex_fixed(
                value
            )

            if result is not None:
                return result

            return self._fmt_hex_float(
                value
            )

        if style == "hex_exp":
            return self._fmt_hex_float(
                value
            )

        if style == "dec_sci":
            return (
                self._fmt_decimal_scientific(
                    value
                )
            )

        return self._fmt_decimal_short(
            value
        )

    def _fmt_float(
        self,
        value: float,
        original: str | None = None,
    ) -> str:
        if not math.isfinite(value):
            if original is not None:
                return original

            return repr(value)

        mode = random.randrange(4)

        if mode == 0:
            return self._fmt_decimal_short(
                value
            )

        if mode == 1:
            return (
                self._fmt_decimal_scientific(
                    value
                )
            )

        if mode == 2:
            result = self._fmt_hex_fixed(
                value
            )

            if result is not None:
                return result

        return self._fmt_hex_float(
            value
        )

    def _fmt_integral_float(
        self,
        value: int,
    ) -> str:
        style = random.choice(
            (
                "hex_exp",
                "hex_fixed",
                "dec_sci",
            )
        )

        return self._fmt_float_style(
            float(value),
            style,
        )

    def _gen_plain_int_expr(
        self,
        value: int,
        depth: int,
    ) -> str:
        if depth <= 0:
            return self._fmt_plain_int(
                value
            )

        op = random.randrange(3)

        if op == 0:
            if value < 0:
                return self._fmt_plain_int(
                    value
                )

            a = random.randint(
                0,
                MAX_INT,
            )
            b = a ^ value

            left = self._gen_plain_int_expr(
                a,
                depth - 1,
            )
            right = self._gen_plain_int_expr(
                b,
                depth - 1,
            )

            return (
                f"({left} ~ {right})"
            )

        if op == 1:
            a = random.randint(
                -1000000,
                1000000,
            )
            b = value - a

            left = self._gen_plain_int_expr(
                a,
                depth - 1,
            )
            right = self._gen_plain_int_expr(
                b,
                depth - 1,
            )

            return (
                f"({left} + {right})"
            )

        a = random.randint(
            -1000000,
            1000000,
        )
        b = a - value

        left = self._gen_plain_int_expr(
            a,
            depth - 1,
        )
        right = self._gen_plain_int_expr(
            b,
            depth - 1,
        )

        return (
            f"({left} - {right})"
        )

    def _random_tiny_quanta(
        self,
    ) -> int:
        q = random.randint(
            1,
            QUANT // 8,
        )

        if random.getrandbits(1):
            q = -q

        return q

    def _random_integral_quanta(
        self,
    ) -> int:
        r = random.randrange(100)

        if r < 35:
            value = random.randint(
                1,
                128,
            )

        elif r < 75:
            value = random.randint(
                128,
                100000,
            )

        else:
            value = random.randint(
                100000,
                8000000,
            )

        if random.getrandbits(1):
            value = -value

        return value * QUANT

    def _random_quanta(
        self,
    ) -> int:
        r = random.randrange(100)

        if r < 14:
            q = random.randint(
                1,
                QUANT // 8,
            )

        elif r < 34:
            q = random.randint(
                QUANT // 8,
                QUANT * 64,
            )

        elif r < 62:
            q = random.randint(
                QUANT * 64,
                QUANT * 65536,
            )

        elif r < 88:
            q = random.randint(
                QUANT * 65536,
                QUANT * 8000000,
            )

        else:
            q = random.randint(
                QUANT * 8000000,
                QUANT * (1 << 30),
            )

        if random.getrandbits(1):
            q = -q

        return q

    def _bitwise_term(
        self,
        value: int,
    ) -> str:
        mode = random.randrange(100)

        if mode < 40:
            operand = (
                self._fmt_integral_float(
                    ~value
                )
            )

            return f"~{operand}"

        if mode < 58:
            operand = (
                self._fmt_integral_float(
                    value
                )
            )

            return f"~(~{operand})"

        if mode < 78:
            key = random.randint(
                1,
                MAX_INT,
            )

            encoded = value ^ key

            left = (
                self._fmt_integral_float(
                    encoded
                )
            )

            right = self._fmt_plain_int(
                key
            )

            return (
                f"({left} ~ {right})"
            )

        if value >= 0:
            operand = (
                self._fmt_integral_float(
                    value - 1
                )
            )

            return f"-~{operand}"

        operand = (
            self._fmt_integral_float(
                -value - 1
            )
        )

        return f"~{operand}"

    def _direct_term(
        self,
        value: float,
        first: bool,
        style: str,
    ) -> str:
        if value == 0.0:
            literal = (
                self._fmt_float_style(
                    0.0,
                    style,
                )
            )

            if first:
                return literal

            return " + " + literal

        if first:
            return self._fmt_float_style(
                value,
                style,
            )

        magnitude = (
            self._fmt_float_style(
                abs(value),
                style,
            )
        )

        r = random.randrange(100)

        if value > 0:
            if r < 65:
                return (
                    " + " + magnitude
                )

            if r < 85:
                return (
                    " - (-"
                    + magnitude
                    + ")"
                )

            return (
                " + ("
                + magnitude
                + ")"
            )

        if r < 45:
            return (
                " + -" + magnitude
            )

        if r < 80:
            return (
                " - " + magnitude
            )

        return (
            " + (-"
            + magnitude
            + ")"
        )

    def _make_style_plan(
        self,
        count: int,
    ) -> list[str]:
        styles = [
            "hex_exp",
            "hex_fixed",
            "dec_sci",
            "dec_short",
        ]

        extras = (
            "hex_exp",
            "hex_fixed",
            "dec_short",
            "hex_exp",
        )

        while len(styles) < count:
            styles.append(
                random.choice(extras)
            )

        styles = styles[:count]

        random.shuffle(styles)

        return styles

    def _wrap_floor_to_int(
        self,
        chain: str,
    ) -> str:
        floor_expr = (
            f"({chain}) // 1"
        )

        r = random.randrange(100)

        if r < 27:
            return (
                f"({floor_expr}|0)"
            )

        if r < 49:
            return (
                f"({floor_expr} ~ 0)"
            )

        if r < 65:
            return (
                f"({floor_expr} & -1)"
            )

        if r < 80:
            return (
                f"({floor_expr} << 0)"
            )

        if r < 92:
            key = random.randint(
                1,
                MAX_INT,
            )

            k = self._fmt_plain_int(
                key
            )

            return (
                f"(({floor_expr} ~ {k})"
                f" ~ {k})"
            )

        if r < 97:
            return (
                f"(({floor_expr}|0) + 0)"
            )

        return (
            f"~(~({floor_expr}))"
        )

    def _gen_float_backed_int(
        self,
        value: int,
    ) -> str:
        count = random.randint(
            FLOAT_CHAIN_MIN,
            FLOAT_CHAIN_MAX,
        )

        frac_q = random.randint(
            QUANT // 8,
            QUANT - QUANT // 8,
        )

        target_q = (
            value * QUANT
            + frac_q
        )

        values = [0] * count

        usable = list(
            range(count - 1)
        )

        tiny_pos = random.choice(
            usable
        )

        bitwise_candidates = [
            i
            for i in usable
            if i != tiny_pos
        ]

        bitwise_pos = (
            random.choice(
                bitwise_candidates
            )
            if bitwise_candidates
            else None
        )

        current_q = 0

        for i in range(count - 1):
            if i == tiny_pos:
                q = (
                    self._random_tiny_quanta()
                )

            elif i == bitwise_pos:
                q = (
                    self._random_integral_quanta()
                )

            else:
                q = self._random_quanta()

            values[i] = q
            current_q += q

        values[-1] = (
            target_q - current_q
        )

        styles = self._make_style_plan(
            count
        )

        parts: list[str] = []

        for i, q in enumerate(values):
            first = i == 0

            if (
                i == bitwise_pos
                and q % QUANT == 0
            ):
                term = self._bitwise_term(
                    q // QUANT
                )

                if first:
                    parts.append(term)
                else:
                    parts.append(
                        " + " + term
                    )

                continue

            parts.append(
                self._direct_term(
                    q / QUANT,
                    first,
                    styles[i],
                )
            )

        chain = "".join(parts)

        return self._wrap_floor_to_int(
            chain
        )

    def _fmt_int_expr(
        self,
        value: int,
        depth: int,
    ) -> str:
        if (
            abs(value)
            <= MAX_FLOAT_BACKED_INT
            and random.random()
            < FLOAT_INT_CHANCE
        ):
            return (
                self._gen_float_backed_int(
                    value
                )
            )

        return self._gen_plain_int_expr(
            value,
            depth,
        )

    def _is_float_literal(
        self,
        token: str,
    ) -> bool:
        t = token.strip().lower()

        if t.startswith("0x"):
            return (
                "." in t
                or "p" in t
            )

        return (
            "." in t
            or "e" in t
        )

    def _make_float_expr(
        self,
        token: str,
    ) -> str:
        try:
            value = _parse_float_token(
                token
            )

            literal = self._fmt_float(
                value,
                token,
            )

        except (
            ValueError,
            OverflowError,
        ):
            return token

        zero = (
            self._gen_plain_int_expr(
                0,
                random.randint(1, 2),
            )
        )

        return (
            f"({zero} + ({literal}))"
        )

    def _validate_expr(
        self,
        expr: str,
    ):
        if "--" in expr:
            raise RuntimeError(
                "NumberObfuscationPass "
                "generated Lua comment token: "
                + expr
            )

        if "(+" in expr:
            raise RuntimeError(
                "NumberObfuscationPass "
                "generated invalid unary plus: "
                + expr
            )

    def obfuscate_token(self, token: str) -> str:
        """Obfuscate one Lua numeric token without requiring a syntax tree.

        VM output emitters use this entry point so generated literal nodes can
        be layered without rendering and reparsing the complete VM source.
        """
        try:
            if self._is_float_literal(token):
                expr = self._make_float_expr(token)
            else:
                value = _parse_int_token(token)
                expr = self._fmt_int_expr(value, random.randint(1, 3))

            self._validate_expr(expr)
            return expr
        except (ValueError, OverflowError):
            return token

    def run(
        self,
        script: str,
        tree,
    ) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in tree.walk():
            if node.type != "number":
                continue
            # string_obf already hides each byte behind a random XOR pair.
            # Re-obfuscating those operands can leave string.char's byte domain
            # under aggressive output-pass combinations and adds no useful
            # protection, so preserve the generated pair verbatim.
            if self._inside_string_char(node, tree):
                continue

            token = tree.text(node)

            expr = self.obfuscate_token(token)

            replacements.append(
                Replacement(
                    start=tree.cs(node),
                    end=tree.ce(node),
                    new_text=expr,
                )
            )

        return replacements
