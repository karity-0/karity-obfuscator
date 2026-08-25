from .pipeline import Pipeline
from .registry import build_pipeline_from_config
from .vm import VMPass
from .passes import (
    StringEncodePass,
    StringObfuscationPass,
    NumberObfuscationPass,
    BooleanObfuscationPass,
    TableObfuscationPass,
    FunctionObfuscationPass,
    RenameObfuscationPass,
    LocalizeGlobalsPass,
    RemoveCommentPass,
    MinifyPass,
    AntiDebugPass,
    OutputSignaturePass,
    SignatureOptions,
)
