import random

from luaparser import astnodes
from .base import BasePass, Replacement


# 부수효과 없이 평가 순서가 결과에 영향을 주지 않는 노드 타입들.
# 이 타입들로만 구성된 key/value는 순서를 바꿔도 안전하다.
_SAFE_LEAF_TYPES = (
    astnodes.Number,
    astnodes.String,
    astnodes.TrueExpr,
    astnodes.FalseExpr,
    astnodes.Nil,
    astnodes.Name,
)

# 순수 연산자 (피연산자가 안전하면 결과도 안전)
_SAFE_OP_TYPES = (
    astnodes.AddOp, astnodes.SubOp, astnodes.MultOp, astnodes.FloatDivOp,
    astnodes.FloorDivOp, astnodes.ModOp, astnodes.ExpoOp,
    astnodes.BAndOp, astnodes.BOrOp, astnodes.BXorOp,
    astnodes.BShiftLOp, astnodes.BShiftROp,
    astnodes.AndLoOp, astnodes.OrLoOp,
    astnodes.EqToOp, astnodes.NotEqToOp,
    astnodes.GreaterThanOp, astnodes.GreaterOrEqThanOp,
    astnodes.LessThanOp, astnodes.LessOrEqThanOp,
    astnodes.Concat,
)

_SAFE_UNOP_TYPES = (
    astnodes.UMinusOp, astnodes.UBNotOp, astnodes.ULNotOp, astnodes.ULengthOP,
)


def _is_multret_expr(node) -> bool:
    """다중값을 반환할 수 있는 표현식인지 (`...`, Call/메서드 호출 포함)."""
    return isinstance(node, (astnodes.Dots, astnodes.Call))


def _is_side_effect_free(node) -> bool:
    """node가 함수 호출/메서드 호출/클로저 생성 없이 평가될 수 있는지 확인.

    Table 리터럴은 재귀적으로 모든 필드를 검사한다.
    """
    if node is None:
        return True

    if isinstance(node, _SAFE_LEAF_TYPES):
        return True

    if isinstance(node, _SAFE_UNOP_TYPES):
        return _is_side_effect_free(node.operand)

    if isinstance(node, _SAFE_OP_TYPES):
        return _is_side_effect_free(node.left) and _is_side_effect_free(node.right)

    if isinstance(node, astnodes.Table):
        for f in node.fields:
            if not _is_side_effect_free(f.key):
                return False
            if not _is_side_effect_free(f.value):
                return False
        return True

    # Call, MethodCall, AnonymousFunction, Index(테이블 접근도 __index 메타메서드
    # 트리거 가능성 있음), Varargs 등은 모두 안전하지 않음으로 취급
    return False


def _field_text(script: str, field) -> tuple[str | None, str]:
    """필드의 (key_text 또는 None, value_text)를 반환.

    array-style 필드(key=None)는 key_text=None.
    record-style(`name=value`)은 key가 Name이지만 위치 정보가 없을 수 있어
    field 전체 텍스트에서 '='로 분리한다.
    bracket-style(`[expr]=value`)은 key 노드의 위치 정보를 사용한다.
    """
    value_text = script[field.value.start_char: field.value.stop_char + 1]

    if field.key is None:
        return None, value_text

    if getattr(field.key, "start_char", None) is not None:
        # [expr]=value 형태: field 전체 텍스트에서 key span 추출
        key_text = script[field.key.start_char: field.key.stop_char + 1]
        return f"[{key_text}]", value_text

    # record-style: name=value, key는 단순 식별자
    if isinstance(field.key, astnodes.Name):
        return f"[\"{field.key.id}\"]", value_text

    # 알 수 없는 형태는 안전하게 통째로 보존 (호출하는 쪽에서 걸러짐)
    return None, value_text


class TableObfuscationPass(BasePass):
    """테이블 리터럴을 명시적 키-값 형태로 재작성하고, 안전한 경우 필드 순서를 섞는다.

    - 배열식 필드(`{1,2,3}`)는 `{[1]=1,[2]=2,[3]=3}` 형태로 명시적 인덱싱
    - record/bracket 필드는 `["key"]=value` / `[expr]=value` 형태로 통일
    - 모든 key/value가 부수효과 없는 표현식으로만 구성된 테이블은 필드 순서를 셔플
      (Call/MethodCall/AnonymousFunction/Index 등이 하나라도 있으면 순서 보존)
    """

    def run(self, script: str, tree) -> list[Replacement]:
        # 중첩 테이블을 안쪽부터 바깥쪽 순서로 처리해야 한다.
        # (start_char가 클수록, 즉 더 안쪽에 있는 테이블일수록 먼저 처리)
        tables = [
            node for node in self.walk(tree)
            if isinstance(node, astnodes.Table)
            and node.start_char is not None
            and node.stop_char is not None
            and node.fields
        ]
        tables.sort(key=lambda n: n.start_char, reverse=True)

        # node id -> 이미 변환된 텍스트 (자식이 먼저 처리되어 있으면 그 결과를 사용)
        rewritten: dict[int, str] = {}
        replacements: list[Replacement] = []

        for node in tables:
            # 마지막 array-style 필드가 다중값을 반환할 수 있는 표현식이면
            # (`{f(), ...}`, `{...}` 등) 명시적 인덱싱으로 변환 시 다중값
            # 펼침 의미가 깨지므로 이 테이블은 통째로 건너뛴다.
            array_fields = [f for f in node.fields if f.key is None]
            if array_fields and _is_multret_expr(array_fields[-1].value):
                continue

            entries: list[str] = []
            array_index = 1
            safe_to_shuffle = True

            for f in node.fields:
                if not _is_side_effect_free(f.key) or not _is_side_effect_free(f.value):
                    safe_to_shuffle = False

                key_text, value_text = _field_text(script, f)

                # value가 이미 처리된 nested table이면 변환된 텍스트로 대체
                if isinstance(f.value, astnodes.Table) and id(f.value) in rewritten:
                    value_text = rewritten[id(f.value)]

                if f.key is None:
                    # array-style: 명시적 인덱스 부여
                    entries.append(f"[{array_index}]={value_text}")
                    array_index += 1
                else:
                    if key_text is None:
                        # 알 수 없는 key 형태 -> 변환 스킵 (이 테이블 전체 보존)
                        safe_to_shuffle = None  # sentinel: bail out entirely
                        break
                    entries.append(f"{key_text}={value_text}")

            if safe_to_shuffle is None:
                continue

            if safe_to_shuffle:
                random.shuffle(entries)

            new_text = "{" + ",".join(entries) + "}"
            rewritten[id(node)] = new_text

            replacements.append(Replacement(
                start=node.start_char,
                end=node.stop_char,
                new_text=new_text,
            ))

        # nested table은 부모 테이블의 new_text에 이미 반영되어 있으므로,
        # 다른 replacement에 완전히 포함되는 replacement는 제거한다.
        def _contained(inner: Replacement, outer: Replacement) -> bool:
            return (outer.start <= inner.start and inner.end <= outer.end
                    and (outer.start, outer.end) != (inner.start, inner.end))

        replacements = [
            r for r in replacements
            if not any(_contained(r, other) for other in replacements)
        ]

        return replacements