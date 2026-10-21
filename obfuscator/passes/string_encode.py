"""Apply the shared String Mosaic spelling policy to source literals."""
from .base import BasePass, Replacement
from .string_obfuscation import parse_lua_string
from .string_mosaic import StringMosaic, StringPolicy, encode_quoted as _encode_bytes


def _encode(raw: str, lua_version='5.3') -> str:
    return StringMosaic(StringPolicy(lua_version=lua_version)).expression(
        parse_lua_string(raw, lua_version))


class StringEncodePass(BasePass):
    """Opt in to shared string spelling; preserve each literal's exact bytes."""
    parser = 'treesitter'

    def __init__(self, lua_version=None):
        self.lua_version = lua_version

    def run(self, script: str, tree) -> list[Replacement]:
        from .literal_mosaic import ACTIVE
        from .function_costs import POLICY
        mosaic = ACTIVE.get()
        version = self.lua_version or (mosaic.policy.lua_version if mosaic is not None else POLICY.get().lua_version)
        generator = (mosaic.strings(force=True) if mosaic is not None and mosaic.policy.lua_version == version
                     else StringMosaic(StringPolicy(lua_version=version)))
        decoded = {}
        replacements = []
        for node in tree.walk():
            if node.type == 'string':
                literal = tree.text(node)
                if literal not in decoded:
                    decoded[literal] = parse_lua_string(literal, version)
                replacements.append(Replacement(tree.cs(node), tree.ce(node),
                    generator.expression(decoded[literal])))
        return replacements
