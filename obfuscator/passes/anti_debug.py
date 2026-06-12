import random
from .base import PrePass


def _junk_loop_body() -> str:
    """무한루프 안에서 의미없는 변수 swap/연산을 반복하는 본문."""
    a, b = random.randint(1, 9999), random.randint(1, 9999)
    var1 = f"_ad{random.randint(1000,9999)}"
    var2 = f"_ad{random.randint(1000,9999)}"
    return (
        f"local {var1},{var2}={a},{b} "
        f"while true do "
        f"{var1},{var2}={var2},{var1} "
        f"{var1}={var1}~{var2} "
        f"{var2}=({var2}+1)%2147483647 "
        f"end"
    )


class AntiDebugPass(PrePass):
    """
    스크립트 전체를 debug.gethook 체크로 감싼다.

    디버거가 debug.sethook으로 후킹을 걸어둔 상태(흔히 인터프리터 단계
    트레이싱/로깅에 사용)면 debug.gethook()이 nil이 아니게 되므로,
    이 경우 원본 코드 대신 무한 junk 루프로 빠진다.

    debug 라이브러리 자체가 제거/샌드박싱된 환경(type(debug)~="table")도
    "정상"으로 취급해 통과시킨다 (과도한 false-positive 방지).

    PrePass(AST 파싱 이전)에서 적용해서, wrapper의 조건식/junk 변수들도
    이후 string/number/rename 등 다른 패스의 난독화 대상이 되게 한다.
    """

    def run(self, script: str) -> str:
        cond_var = f"_ad{random.randint(1000,9999)}"
        junk = _junk_loop_body()

        return (
            f'local {cond_var}=(type(debug)~="table") '
            f'or (debug.gethook==nil) or (debug.gethook()==nil)\n'
            f'if {cond_var} then\n'
            f'{script}\n'
            f'else\n'
            f'{junk}\n'
            f'end\n'
        )