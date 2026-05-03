from .base import BasePass, PrePass, Replacement
from .string_encode import StringEncodePass
from .number_obfuscation import NumberObfuscationPass
from .remove_comment import RemoveCommentPass

__all__ = ["BasePass", "Replacement"]