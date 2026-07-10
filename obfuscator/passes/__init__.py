from .base import BasePass, PrePass, PostPass, Replacement
from .string_encode import StringEncodePass
from .string_obfuscation import StringObfuscationPass
from .number_obfuscation import NumberObfuscationPass
from .boolean_obfuscation import BooleanObfuscationPass
from .table_obfuscation import TableObfuscationPass
from .function_obfuscation import FunctionObfuscationPass
from .rename_obfuscation import RenameObfuscationPass
from .localize_globals import LocalizeGlobalsPass
from .remove_comment import RemoveCommentPass
from .minify import MinifyPass
from .anti_debug import AntiDebugPass
from .anti_decompile import AntiDecompilePass
from .packer import PackerPass