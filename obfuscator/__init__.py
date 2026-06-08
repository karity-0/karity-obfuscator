from .pipeline import Pipeline
from .passes import (
    StringEncodePass,
    StringObfuscationPass,
    NumberObfuscationPass,
    BooleanObfuscationPass,
    RenameObfuscationPass,
    RemoveCommentPass,
    MinifyPass,
    VMPass,
)