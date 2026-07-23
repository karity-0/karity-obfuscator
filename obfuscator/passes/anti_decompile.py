import random
from .base import BasePass, Replacement


# 미끼 로컬이 차지할 슬롯(0..N-1)에 대응하는, unluac가 붙일 이름들.
# guard는 이 이름들(디컴파일 시 truthy 로컬)만 참조해 확실히 발동시킨다.
_DECOY_COUNT = 3
_SENTINELS = [f"L{i}_1" for i in range(_DECOY_COUNT)]  # L0_1, L1_1, L2_1

# 삽입 가능한 statement 경계 중 guard를 심을 비율과 상·하한.
_GUARD_RATE = 0.22
_GUARD_MIN = 5
_GUARD_MAX = 60


def _truthy_literal() -> str:
    """디컴파일된 소스에서도 truthy로 살아남는 값(nil/false만 falsy)."""
    return random.choice([
        "true",
        str(random.randint(1, 9999)),
        '"' + "".join(random.choice("abcdef") for _ in range(4)) + '"',
    ])


def _junk_body() -> str:
    """그럴싸해 보이는 무의미 연산. guard가 발동(디컴파일)될 때만 실행되고
    원본에서는 절대 실행되지 않으므로 부작용이 없다. 이후 rename/number/
    string 패스가 추가로 난독화해 주변 코드와 섞인다."""
    a, b = random.randint(1, 9999), random.randint(1, 9999)
    v1 = f"_ac{random.randint(1000,9999)}"
    v2 = f"_ac{random.randint(1000,9999)}"
    op = random.choice(["~", "+", "*", "%"])
    return (
        f"local {v1},{v2}={a},{b} "
        f"{v1}={v1}{op}{v2} "
        f"{v2}=({v2}*{random.randint(2,9)}+{random.randint(1,99)})%2147483647"
    )


def _guard() -> str:
    """무작위 형태의 anti-decompile guard 한 개.

    셋 다 공통 성질: sentinel이 nil(원본)이면 무해(0회/스킵), truthy
    (디컴파일)이면 무한루프로 hang. 형태·이름·본문을 매번 다르게 해서
    정규식 하나로 일괄 제거되지 않게 한다."""
    sent = random.choice(_SENTINELS)
    junk = _junk_body()
    form = random.randint(0, 2)
    if form == 0:
        # 원본: nil이라 0회. 디컴파일: truthy라 무한.
        return f"while {sent} do {junk} end "
    if form == 1:
        return f"if {sent} then {junk} while true do end end "
    # for 상한이 sentinel에 의해 0(원본) / 무한대(디컴파일)로 갈린다.
    start = random.randint(1, 5)
    return f"for _={start},({sent} and 1/0 or 0) do {junk} end "


class AntiDecompilePass(BasePass):
    """
    소스코드단 디컴파일러(unluac) 방지 — 흩뿌린 guard 방식.

    원리
    ----
    unluac는 디버그 이름 정보가 없는 로컬을 슬롯 번호 기준 `L0_1`, `L1_1` …
    로 복원한다. 이 패스는:

    1. 청크 최상단(슬롯 0..N-1)에 truthy 미끼 로컬을 심는다. 컴파일 후 이
       슬롯들은 디컴파일 시 정확히 `L0_1`, `L1_1` … 로 이름 붙는다.
    2. 코드 곳곳의 statement 경계에 작은 guard를 무작위로 흩뿌린다:

           while L0_1 do <junk> end
           if L1_1 then <junk> while true do end end
           for _=3,(L2_1 and 1/0 or 0) do <junk> end

    원본 바이트코드에서 `L0_1` 등은 로컬로 선언된 적이 없어 전역 참조
    (런타임 nil)로 컴파일된다. 따라서 모든 guard는 무해하게 스킵되고 원본은
    정상 동작한다.

    공격자가 바이트코드를 unluac로 디컴파일하면 미끼 로컬이 `L0_1` 등으로
    이름 붙고, guard의 `L0_1`(원래 전역)이 그 로컬에 shadow돼 truthy가 된다
    → 무한루프로 hang. **단 하나의 guard만 살아남아도** 디컴파일본이 깨지므로,
    공격자는 흩어진 guard를 전부 찾아 제거해야 한다(단일 if/else 래퍼를
    지우는 것보다 훨씬 번거로움). 게다가 디컴파일된 소스에서는 모든 로컬이
    `L#_#` 꼴이라 sentinel 참조가 완벽히 위장된다.

    왜 BasePass인가: statement 경계에 안전하게 삽입하려면 파싱 트리가 필요하고,
    삽입한 미끼/junk가 이후 rename/number/string 패스로 추가 난독화돼 주변
    코드와 섞이도록 초반 base 패스로 두는 것이 유리하다. sentinel 이름
    (`L0_1` …)은 전역 참조라 localize_globals 화이트리스트(_KNOWN_*)에 없고,
    로컬 선언이 아니라 rename_obf도 건드리지 않아 그대로 보존된다.

    미끼가 슬롯 0부터 배치되도록 config의 base 패스 중 *가장 앞*에 두는 것이
    이상적이다.
    """

    parser = "treesitter"

    def run(self, script: str, ctx) -> list[Replacement]:
        # 1) 삽입 가능한 statement 경계 수집: chunk/block의 named 자식 시작 위치.
        candidates: set[int] = set()
        for node in ctx.walk():
            if node.type not in ("chunk", "block"):
                continue
            for c in node.children:
                if not c.is_named or c.type == "comment":
                    continue
                pos = ctx.cs(c)
                if pos > 0:  # 0은 미끼 선언용으로 예약
                    candidates.add(pos)

        replacements: list[Replacement] = []

        # 2) 미끼 로컬 선언을 청크 최상단(pos 0)에 삽입 → 슬롯 0..N-1 확보.
        decoy_vars = ",".join(f"_ac{random.randint(1000,9999)}"
                              for _ in range(_DECOY_COUNT))
        decoy_vals = ",".join(_truthy_literal() for _ in range(_DECOY_COUNT))
        decoy = f"local {decoy_vars}={decoy_vals} "
        replacements.append(Replacement(start=0, end=-1, new_text=decoy))

        # 3) guard를 무작위 statement 경계에 흩뿌린다.
        if candidates:
            n = max(_GUARD_MIN, round(len(candidates) * _GUARD_RATE))
            n = min(n, _GUARD_MAX, len(candidates))
            for pos in random.sample(sorted(candidates), n):
                replacements.append(
                    Replacement(start=pos, end=pos - 1, new_text=_guard()))

        return replacements
