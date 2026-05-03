import re
from .base import PrePass

class RemoveCommentPass(PrePass):
    def run(self, script: str) -> str:
        return self._remove(script)

    def _remove(self, src: str) -> str:
        result = []
        i = 0
        n = len(src)
        while i < n:
            if src[i] == '[':
                m = re.match(r'\[(?P<eq>=*)\[', src[i:])
                if m:
                    eq = m.group('eq')
                    close = f']{eq}]'
                    end = src.find(close, i + len(m.group(0)))
                    if end != -1:
                        result.append(src[i:end + len(close)])
                        i = end + len(close)
                        continue
            if src[i] in ('"', "'"):
                quote = src[i]
                result.append(quote)
                i += 1
                while i < n:
                    c = src[i]
                    if c == '\\':
                        result.append(c)
                        i += 1
                        if i < n:
                            result.append(src[i])
                    elif c == quote:
                        result.append(c)
                        break
                    else:
                        result.append(c)
                    i += 1
                i += 1
                continue
            if src[i:i+2] == '--':
                m = re.match(r'--\[(?P<eq>=*)\[', src[i:])
                if m:
                    eq = m.group('eq')
                    close = f']{eq}]'
                    end = src.find(close, i + len(m.group(0)))
                    if end != -1:
                        i = end + len(close)
                        continue
                while i < n and src[i] != '\n':
                    i += 1
                continue
            result.append(src[i])
            i += 1
        return ''.join(result)