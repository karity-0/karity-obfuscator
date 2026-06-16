import re
import bisect
from luaparser import astnodes, ast
from .base import BasePass, Replacement

# 문자열 리터럴, 주석, 숫자를 보호하면서 식별자만 추출하는 정규식
_TOKEN_RE = re.compile(
    r'(?P<longstr>\[(?P<leq>=*)\[.*?\](?P=leq)\])'
    r'|(?P<str>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')'
    r'|(?P<longcmt>--\[(?P<ceq>=*)\[.*?\](?P=ceq)\])'
    r'|(?P<cmt>--[^\n]*)'
    r'|(?P<num>0[xX](?:[0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)(?:[pP][+-]?\d+)?|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)'
    r'|(?P<ident>[A-Za-z_]\w*)',
    re.DOTALL,
)


def subtract_interval(intervals: list[tuple[int, int]], drop_start: int, drop_end: int) -> list[tuple[int, int]]:
    """기존 인터벌 목록에서 특정 구간(drop_start ~ drop_end)을 제외한 서브 인터벌들을 반환합니다."""
    new_intervals = []
    for s, e in intervals:
        if e < drop_start or s > drop_end:
            new_intervals.append((s, e))
        else:
            if s < drop_start:
                new_intervals.append((s, drop_start - 1))
            if e > drop_end:
                new_intervals.append((drop_end + 1, e))
    return new_intervals


_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
}


def _in_ranges(pos: int, ranges: list[tuple[int, int]]) -> bool:
    # ranges는 start 기준 정렬된 상태여야 함
    idx = bisect.bisect_right(ranges, (pos, float('inf'))) - 1
    if idx >= 0 and ranges[idx][0] <= pos <= ranges[idx][1]:
        return True
    return False


def _field_key_ranges(script: str, tree) -> list[tuple[int, int]]:
    ranges = []
    for node in ast.walk(tree):
        if not isinstance(node, astnodes.Field):
            continue

        start = getattr(node, "start_char", None)
        stop = getattr(node, "stop_char", None)
        if start is None or stop is None:
            continue

        text = script[start:stop + 1]
        match = re.match(r"\s*([A-Za-z_]\w*)\s*=", text, re.DOTALL)
        if match:
            key_start = start + match.start(1)
            key_end = start + match.end(1) - 1
            ranges.append((key_start, key_end))
    return ranges


def _rename_segment(segment: str, name_map: dict[str, str], base_offset: int = 0,
                    skip_ranges: list[tuple[int, int]] | None = None) -> str:
    skip_ranges = skip_ranges or []

    def replace(m: re.Match) -> str:
        if m.group('ident'):
            ident = m.group('ident')
            global_start = base_offset + m.start()

            if ident in _KEYWORDS or _in_ranges(global_start, skip_ranges):
                return ident

            prev = m.start() - 1
            while prev >= 0 and segment[prev].isspace():
                prev -= 1
            if prev >= 0 and segment[prev] == ":":
                return ident
            if prev >= 0 and segment[prev] == "." and not (prev > 0 and segment[prev - 1] == "."):
                return ident

            return name_map.get(ident, ident)
        return m.group(0)
    return _TOKEN_RE.sub(replace, segment)

def _get_scope_range(s, tree, script: str) -> tuple[int, int]:
    if s is tree:
        return 0, len(script) - 1
    
    start = getattr(s, 'start_char', 0)
    stop = getattr(s, 'stop_char', len(script) - 1)
    
    if isinstance(s, astnodes.LocalFunction):
        idx = script.find('(', start)
        if idx != -1 and idx < stop:
            start = idx
            
    return start, stop


class RenameObfuscationPass(BasePass):
    # tree-sitter 기반 분석 (luaparser 대비 ~10x). 파이프라인이 제공한
    # TSContext를 그대로 재사용해 이중 파싱을 피한다.
    parser = "treesitter"

    def run(self, script: str, tree) -> list[Replacement]:
        from .rename_ts import rename_with_ctx
        return [Replacement(start=0, end=len(script) - 1,
                            new_text=rename_with_ctx(tree))]

    def _run_luaparser(self, script: str, tree) -> list[Replacement]:
        counter = [0]
        skip_ranges = sorted(_field_key_ranges(script, tree))

        scopes = [tree]
        for node in ast.walk(tree):
            if isinstance(node, (astnodes.LocalFunction, astnodes.Function, astnodes.AnonymousFunction)):
                scopes.append(node)

        scope_ranges = {id(s): _get_scope_range(s, tree, script) for s in scopes}
        scopes_asc = sorted(scopes, key=lambda n: scope_ranges[id(n)][1] - scope_ranges[id(n)][0] if n is not tree else float('inf'))

        def get_closest_scope(target_node):
            t_start = getattr(target_node, 'start_char', None)
            t_stop = getattr(target_node, 'stop_char', None)
            if t_start is None or t_stop is None:
                return tree
                
            for s in scopes_asc:
                if s is tree:
                    return tree
                s_start, s_stop = scope_ranges[id(s)]
                if s_start <= t_start and t_stop <= s_stop:
                    return s
            return tree

        scope_names = {id(s): set() for s in scopes}

        for s in scopes:
            if s is not tree:
                for arg in s.args:
                    if isinstance(arg, astnodes.Name):
                        scope_names[id(s)].add(arg.id)

        for node in ast.walk(tree):
            if isinstance(node, astnodes.LocalAssign):
                s = get_closest_scope(node)
                for t in node.targets:
                    if isinstance(t, astnodes.Name):
                        scope_names[id(s)].add(t.id)

            elif isinstance(node, astnodes.LocalFunction):
                t_start = getattr(node, 'start_char', None)
                t_stop = getattr(node, 'stop_char', None)
                parent_scope = tree
                if t_start is not None and t_stop is not None:
                    for s in scopes_asc:
                        if s is not node and s is not tree:
                            s_start, s_stop = scope_ranges[id(s)]
                            if s_start <= t_start and t_stop <= s_stop:
                                parent_scope = s
                                break
                if isinstance(node.name, astnodes.Name):
                    scope_names[id(parent_scope)].add(node.name.id)
            elif isinstance(node, astnodes.Fornum):
                s = get_closest_scope(node)
                if isinstance(node.target, astnodes.Name):
                    scope_names[id(s)].add(node.target.id)
            elif isinstance(node, astnodes.Forin):
                s = get_closest_scope(node)
                for t in node.targets:
                    if isinstance(t, astnodes.Name):
                        scope_names[id(s)].add(t.id)

        scopes_desc = sorted(scopes, key=lambda n: scope_ranges[id(n)][1] - scope_ranges[id(n)][0] if n is not tree else float('inf'), reverse=True)
        scope_maps = {}

        for s in scopes_desc:
            parent_map = {}
            if s is not tree:
                s_start, s_stop = scope_ranges[id(s)]
                for potential_parent in scopes_asc:
                    if potential_parent is not s and potential_parent is not tree:
                        p_start, p_stop = scope_ranges[id(potential_parent)]
                        if p_start <= s_start and s_stop <= p_stop:
                            parent_map = scope_maps[id(potential_parent)]
                            break
                if not parent_map:
                    parent_map = scope_maps[id(tree)]

            current_map = parent_map.copy()
            for name in sorted(scope_names[id(s)], key=len, reverse=True):
                current_map[name] = f"_v{counter[0]}"
                counter[0] += 1
            scope_maps[id(s)] = current_map

        scope_intervals = {}
        for s in scopes:
            s_start, s_stop = scope_ranges[id(s)]
            scope_intervals[id(s)] = [(s_start, s_stop)]

        for parent in scopes:
            p_start, p_stop = scope_ranges[id(parent)]
            for child in scopes:
                if parent is child:
                    continue
                c_start, c_stop = scope_ranges[id(child)]
                if p_start <= c_start and c_stop <= p_stop:
                    scope_intervals[id(parent)] = subtract_interval(
                        scope_intervals[id(parent)], c_start, c_stop
                    )

        all_ops = []
        for s in scopes:
            for start, end in scope_intervals[id(s)]:
                if start <= end:
                    all_ops.append((start, end, scope_maps[id(s)]))

        all_ops.sort(key=lambda x: x[0], reverse=True)

        result = script
        for start, end, name_map in all_ops:
            new_seg = _rename_segment(result[start:end + 1], name_map, start, skip_ranges)
            result = result[:start] + new_seg + result[end + 1:]

        return [Replacement(start=0, end=len(script) - 1, new_text=result)]