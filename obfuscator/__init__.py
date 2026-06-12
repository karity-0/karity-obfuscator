from .pipeline import Pipeline
from .registry import build_pipeline_from_config
from .passes import (
    StringEncodePass,
    StringObfuscationPass,
    NumberObfuscationPass,
    BooleanObfuscationPass,
    RenameObfuscationPass,
    RemoveCommentPass,
    MinifyPass,
    VMPass,
    AntiDebugPass,
    TableObfuscationPass, 
)