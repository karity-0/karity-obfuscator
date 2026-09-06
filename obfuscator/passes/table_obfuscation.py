import random

from .base import BasePass, Replacement


# 부수효과 없이 평가 순서가 결과에 영향을 주지 않는 leaf 노드 타입들.
_SAFE_LEAF_TYPES = {"number", "string", "true", "false", "nil", "identifier"}

# 다중값 반환 가능 표현식 (`...`, 함수/메서드 호출)
_MULTRET_TYPES = {"function_call", "vararg_expression"}


def _is_multret_expr(node) -> bool:
    return node is not None and node.type in _MULTRET_TYPES


def _is_side_effect_free(node) -> bool:
    """node가 함수 호출/인덱스 접근/클로저 생성 없이 평가될 수 있는지.

    Table 리터럴은 재귀적으로 모든 필드를 검사한다. 알 수 없는 타입은
    보수적으로 unsafe(=순서 보존)로 취급한다.
    """
    if node is None:
        return True

    t = node.type
    if t in _SAFE_LEAF_TYPES:
        return True

    if t in {"unary_expression", "binary_expression"}:
        # Even identifier-only arithmetic may invoke Lua metamethods.  Without
        # type proof, reordering these expressions is not semantics-preserving.
        return False

    if t == "table_constructor":
        for f in _fields(node):
            key, value, _ = _parse_field(f)
            if not _is_side_effect_free(key) or not _is_side_effect_free(value):
                return False
        return True

    # function_call / *_index_expression / function_definition /
    # vararg_expression 등은 모두 안전하지 않음으로 취급
    return False


def _fields(table_node):
    return [c for c in table_node.children if c.type == "field"]


def _parse_field(field):
    """field 노드를 (key_node|None, value_node, kind)로 분해.

    kind: "array" (`v`), "record" (`name=v`), "bracket" (`[expr]=v`)
    """
    ch = field.children
    eq_idx = next((i for i, c in enumerate(ch) if c.type == "="), None)
    if eq_idx is None:
        # array-style: 단일 값 표현식
        return None, (ch[0] if ch else None), "array"
    value = ch[eq_idx + 1]
    if ch[0].type == "[":
        return ch[1], value, "bracket"   # [expr]=value
    return ch[0], value, "record"        # name=value (key는 identifier)


def _field_text(tree, field) -> tuple[str | None, str]:
    """필드의 (key_text 또는 None, value_text)를 반환."""
    key, value, kind = _parse_field(field)
    value_text = tree.text(value)
    if kind == "array":
        return None, value_text
    if kind == "bracket":
        return f"[{tree.text(key)}]", value_text
    # record: name=value → ["name"]=value
    return f'["{tree.text(key)}"]', value_text


class TableObfuscationPass(BasePass):
    """테이블 리터럴을 명시적 키-값 형태로 재작성하고, 안전하면 필드 순서를 섞는다.

    - 배열식 필드(`{1,2,3}`)는 `{[1]=1,[2]=2,[3]=3}` 형태로 명시적 인덱싱
    - record/bracket 필드는 `["key"]=value` / `[expr]=value` 형태로 통일
    - 모든 key/value가 부수효과 없는 리터럴만 변환하고 필드 순서를 셔플
    - 호출/metamethod/index 접근이 섞인 테이블은 keyed-field 변환 자체가 Lua의
      평가 순서를 바꿀 수 있으므로 원문을 보존
    """
    parser = "treesitter"

    def run(self, script: str, tree) -> list[Replacement]:
        # 중첩 테이블을 안쪽(start_char 큰 것)부터 처리한다.
        tables = [
            node for node in tree.walk()
            if node.type == "table_constructor" and _fields(node)
        ]
        tables.sort(key=lambda n: tree.cs(n), reverse=True)

        rewritten: dict[int, str] = {}     # node.id -> 변환된 텍스트
        replacements: list[Replacement] = []

        for node in tables:
            fields = _fields(node)

            # 마지막 array 필드가 다중값 표현식이면 명시적 인덱싱으로
            # 펼침 의미가 깨지므로 이 테이블은 통째로 건너뛴다.
            array_fields = [f for f in fields if _parse_field(f)[2] == "array"]
            if array_fields and _is_multret_expr(_parse_field(array_fields[-1])[1]):
                continue

            entries: list[str] = []
            array_index = 1
            safe_to_shuffle = True
            bail = False

            for f in fields:
                key, value, kind = _parse_field(f)
                if not _is_side_effect_free(key) or not _is_side_effect_free(value):
                    safe_to_shuffle = False

                key_text, value_text = _field_text(tree, f)

                # value가 이미 처리된 nested table이면 변환된 텍스트로 대체
                if value is not None and value.type == "table_constructor" \
                        and value.id in rewritten:
                    value_text = rewritten[value.id]

                if kind == "array":
                    entries.append(f"[{array_index}]={value_text}")
                    array_index += 1
                else:
                    if key_text is None:
                        bail = True
                        break
                    entries.append(f"{key_text}={value_text}")

            if bail or not safe_to_shuffle:
                continue

            random.shuffle(entries)

            new_text = "{" + ",".join(entries) + "}"
            rewritten[node.id] = new_text

            replacements.append(Replacement(
                start=tree.cs(node),
                end=tree.ce(node),
                new_text=new_text,
            ))

        # nested table은 부모의 new_text에 이미 반영되므로, 다른 replacement에
        # 완전히 포함되는 replacement는 제거한다.
        def _contained(inner: Replacement, outer: Replacement) -> bool:
            return (outer.start <= inner.start and inner.end <= outer.end
                    and (outer.start, outer.end) != (inner.start, inner.end))

        replacements = [
            r for r in replacements
            if not any(_contained(r, other) for other in replacements)
        ]

        return replacements
