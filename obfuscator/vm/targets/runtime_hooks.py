"""Checked target boundaries in shared runtime templates."""
import re


def replace_hook(source: str, name: str, body: str, *, expected: int = 1) -> str:
    start, end = f'--<<TARGET_{name}>>', f'--<<ENDTARGET_{name}>>'
    pattern = re.compile(re.escape(start) + r'.*?' + re.escape(end), re.S)
    if (source.count(start) != expected or source.count(end) != expected
            or len(pattern.findall(source)) != expected):
        raise ValueError(f'target runtime hook {name}: expected {expected} complete boundaries')
    return pattern.sub(lambda match: start + '\n' + body + '\n' + end, source)
