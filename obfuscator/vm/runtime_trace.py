"""Select trace instrumentation before any runtime obfuscation or hashing."""

START = "--<<RUNTIME_TRACE>>"
END = "--<<ENDRUNTIME_TRACE>>"


def apply_runtime_trace(source: str, enabled: bool) -> str:
    result = []
    tracing = False
    for line in source.splitlines(keepends=True):
        marker = line.strip()
        if marker == START:
            if tracing:
                raise ValueError("nested runtime trace section")
            tracing = True
        elif marker == END:
            if not tracing:
                raise ValueError("unexpected runtime trace section end")
            tracing = False
        elif enabled or not tracing:
            result.append(line)
    if tracing:
        raise ValueError("unterminated runtime trace section")
    return "".join(result)
