from .base import BasePass, PrePass, PostPass, Replacement
from .string_encode import StringEncodePass
from .string_obfuscation import StringObfuscationPass
from .number_obfuscation import NumberObfuscationPass
from .boolean_obfuscation import BooleanObfuscationPass
from .rename_obfuscation import RenameObfuscationPass
from .remove_comment import RemoveCommentPass
from .minify import MinifyPass
from .vm_pass import VMPass
from .anti_debug import AntiDebugPass