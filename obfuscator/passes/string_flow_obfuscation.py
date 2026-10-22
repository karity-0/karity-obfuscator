"""The staged string reconstruction introduced in 1.2, now a separate pass."""
from .string_obfuscation import StringObfuscationPass, _encode_flow


class StringFlowObfuscationPass(StringObfuscationPass):
    """Interleave mutable word/state reconstruction before assembling bytes."""
    encoder = staticmethod(_encode_flow)

    def __init__(self, **options):
        from .string_reconstruction import validate_options
        validate_options(options)
        self.options = options
