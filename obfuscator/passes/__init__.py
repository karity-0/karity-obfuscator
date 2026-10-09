# Python 3.15 defers these exports until first use; older versions import normally.
__lazy_modules__ = {
    'obfuscator.passes.base',
    'obfuscator.passes.string_encode',
    'obfuscator.passes.string_obfuscation',
    'obfuscator.passes.number_obfuscation',
    'obfuscator.passes.meme_strings',
    'obfuscator.passes.boolean_obfuscation',
    'obfuscator.passes.table_obfuscation',
    'obfuscator.passes.function_obfuscation',
    'obfuscator.passes.rename_obfuscation',
    'obfuscator.passes.strip_info',
    'obfuscator.passes.localize_globals',
    'obfuscator.passes.remove_comment',
    'obfuscator.passes.minify',
    'obfuscator.passes.anti_debug',
    'obfuscator.passes.anti_decompile',
    'obfuscator.passes.packer',
    'obfuscator.passes.output_signature',
}

from .base import BasePass, PrePass, PostPass, Replacement
from .string_encode import StringEncodePass
from .string_obfuscation import StringObfuscationPass
from .number_obfuscation import NumberObfuscationPass
from .meme_strings import MemeStringsPass
from .boolean_obfuscation import BooleanObfuscationPass
from .table_obfuscation import TableObfuscationPass
from .function_obfuscation import FunctionObfuscationPass
from .rename_obfuscation import RenameObfuscationPass
from .strip_info import StripInfoPass
from .localize_globals import LocalizeGlobalsPass
from .remove_comment import RemoveCommentPass
from .minify import MinifyPass
from .anti_debug import AntiDebugPass
from .anti_decompile import AntiDecompilePass
from .packer import PackerPass
from .output_signature import OutputSignaturePass, SignatureOptions
