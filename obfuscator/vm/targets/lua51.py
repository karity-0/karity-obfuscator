"""Lua 5.1 target adapter for the shared backend runtime representations."""
from pathlib import Path
import random
import re
from .lua51_syntax import translate
from .capabilities import Capability as C, TargetRequirements
from .dump51 import normalize_dump
from .tools51 import run as run_tool

_ROOT = Path(__file__).parent
_HELPER = "_target51"
_NATIVE_HOOK_NAMES = {
    'WORD_READ', 'INSTRUCTION_READ', 'SIGNED_READ', 'FLOAT_READ', 'CRC',
    'INSTRUCTION_XOR', 'INSTRUCTION_STATE_KEY', 'INSTRUCTION_FIELDS', 'WORD_REKEY',
    'INTEGRITY_DECODE', 'INTEGRITY_MIX', 'INTEGRITY_EXPRESSION',
    'INSTRUCTION_DECODE',
    'INTEGER_DIGITS', 'FLOAT_DIGITS',
    'FLOAT_RESULT', 'MOV_FLOAT_STORAGE', 'FUNCTION_DUMP', 'RUNTIME_API', 'PRIVATE_MIX',
    'SOURCE_VALUE',
    'INSTRUCTION_KEYSTREAM', 'STRING_KEYSTREAM', 'USER_EXPRESSION', 'USER_STATEMENT',
    'BLOB_BASE', 'BLOB_CIPHER', 'READER_PRIMITIVES', 'ARGUMENT_PACKET',
    'PROTO_CODE', 'PROTO_METADATA', 'PROTO_CHILDREN',
    'CONSTANT_RESOLVER', 'FAKE_CONSTANT_SKIP',
    'TAMPER',
    'REGISTER_MAP',
    'PRIVATE_GRAPH', 'PRIVATE_EXPRESSION', 'PRIVATE_LOW_EXPRESSION',
    'PRIVATE_MOD_EXPRESSION',
    '51_PRIVATE_MIX',
    '51_KARITY_REGISTERS',
    '51_KARITY_REGISTER_BANK',
    '51_KARITY_PENDING',
    '51_KARITY_GRAPH_STATE',
    '51_KARITY_FETCH',
    '51_KARITY_HANDLER_CHAIN',
    '51_KARITY_CONTROL_HELPERS',
    '51_KARITY_VALUE_STORAGE',
    'MOV_UINT',
    '51_MOV_NATIVE',
    'EXEC_PRIVATE_BINDINGS',
    'CLASSIC_EXEC_NATIVE',
    'KARITY_EXEC_STATE',
}
_TARGET_MARKER_RE = re.compile(
    r'--<<(?P<end>END)?TARGET_(?P<name>[A-Z0-9_]+)>>'
)
_NATIVE_API_MEMBERS = {
    '_native_string_dump': 'string.dump',
    '_native_string_byte': 'string.byte',
    '_native_string_char': 'string.char',
    '_native_string_format': 'string.format',
    '_native_table_concat': 'table.concat',
    '_native_math_floor': 'math.floor',
    '_native_math_ceil': 'math.ceil',
    '_native_math': 'math', '_native_string': 'string',
    '_native_table': 'table', '_native_debug': 'debug',
    '_native_type': 'type', '_native_tostring': 'tostring',
    '_native_tonumber': 'tonumber', '_native_select': 'select',
    '_native_error': 'error', '_native_rawget': 'rawget',
    '_native_rawset': 'rawset', '_native_getfenv': 'getfenv',
    '_native_setfenv': 'setfenv', '_native_unpack': 'unpack',
}
_NATIVE_ALIASES = {
    name: '_native_api.' + member for name, member in _NATIVE_API_MEMBERS.items()
}


def _replace_lua_nodes(source, replacements):
    """Replace exact Lua syntax nodes, never text inside strings or comments."""
    from ...passes.ts_utils import parse

    context = parse(source)
    matches = []
    for node in context.walk():
        mapping = replacements.get(node.type)
        if mapping is None:
            continue
        replacement = mapping.get(context.text(node))
        if replacement is not None:
            matches.append((context.cs(node), context.ce(node) + 1, replacement))
    # A selected call or member expression owns its nested identifiers. Pick
    # the widest node at a start position, then apply disjoint edits in reverse.
    matches.sort(key=lambda item: (item[0], item[0] - item[1]))
    selected = []
    occupied_until = -1
    for start, end, replacement in matches:
        if start >= occupied_until:
            selected.append((start, end, replacement))
            occupied_until = end
    for start, end, replacement in reversed(selected):
        source = source[:start] + replacement + source[end:]
    return source


def _promote_native_hook_markers(source):
    """Keep target-native regions recognizable across output comment passes."""
    def promote(match):
        name = match.group('name')
        if name not in _NATIVE_HOOK_NAMES or name == 'CLASSIC_EXEC_NATIVE':
            return match.group(0)
        if name.startswith('51_NATIVE_'):
            return match.group(0)
        end = match.group('end') or ''
        return f'--<<{end}TARGET_51_NATIVE_{name}>>'
    return _TARGET_MARKER_RE.sub(promote, source)


def _compact_executor_captures(source):
    """Bank immutable helper bindings, not user values or mutable VM state.

    Run after private-graph lowering: that lowering can introduce new helper
    references even after the backend's executor was finalized.
    """
    from ...passes.ts_utils import parse
    from ...passes.rename_ts import resolve_bindings, _apply_replacements_once

    ctx = parse(source)
    bindings, free_names, _, _, _ = resolve_bindings(ctx)
    used_names = {b.original for b in bindings} | free_names
    replacements = []
    bank_index = 0
    for node in ctx.walk():
        if node.type not in ('function_definition', 'function_declaration'):
            continue
        params = node.child_by_field_name('parameters')
        if params is None or not re.match(r'\(\s*proto\s*,\s*upvals\s*,', ctx.text(params)):
            continue
        captured = [b for b in bindings
                    if not node.start_byte <= b.nodes[0].start_byte < node.end_byte
                    and any(node.start_byte <= n.start_byte < node.end_byte
                            for n in b.nodes[1:])]
        if len(captured) < 55:
            continue
        helpers = []
        for binding in captured:
            declaration = binding.nodes[0].parent
            if declaration.type != 'function_declaration' or declaration.children[0].type != 'local':
                continue
            # A reassigned local function is a mutable cell and cannot be copied.
            if any(n.parent.type == 'variable_list' or
                   (n.parent.type == 'function_declaration' and
                    n.parent.child_by_field_name('name') == n)
                   for n in binding.nodes[1:]):
                continue
            helpers.append(binding)
        if not helpers:
            continue
        bank_index += 1
        bank = f'_native_capture_bank_{bank_index}'
        while bank in used_names:
            bank += '_'
        used_names.add(bank)
        statement = node
        while statement.parent is not None and statement.parent.type not in ('block', 'chunk'):
            statement = statement.parent
        position = ctx.cs(statement)
        replacements.append((position, position - 1,
                             'local ' + bank + '={' + ','.join(b.original for b in helpers) + '}\n'))
        for index, binding in enumerate(helpers, 1):
            for reference in binding.nodes[1:]:
                if node.start_byte <= reference.start_byte < node.end_byte:
                    replacements.append((ctx.cs(reference), ctx.ce(reference), f'{bank}[{index}]'))
    return _apply_replacements_once(source, replacements)


def _translate_preserving_native_hooks(source, *, translate_general=False):
    from .lua51_syntax import translate_private_graph, translate_private_modulo, translate_private_low
    private_graph_pattern = re.compile(
        r'(--<<TARGET_PRIVATE_GRAPH>>)(.*?)(--<<ENDTARGET_PRIVATE_GRAPH>>)',re.S)
    source = private_graph_pattern.sub(
        lambda match: match.group(1) + '\n' +
        translate_private_graph(match.group(2)) + '\n' + match.group(3),
        source,
    )
    private_low_pattern = re.compile(
        r'--<<TARGET_PRIVATE_LOW_EXPRESSION:(?P<modulus>\d+)>>(.*?)'
        r'--<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>',re.S)
    def lower_private_low(match):
        translated=translate_private_low(match.group(2), int(match.group('modulus')))
        return ('--<<TARGET_PRIVATE_LOW_EXPRESSION>>\n'+translated+'\n'+
                '--<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>')
    source=private_low_pattern.sub(lower_private_low,source)
    private_mod_pattern = re.compile(
        r'(--<<TARGET_PRIVATE_MOD_EXPRESSION>>)(.*?)'
        r'(--<<ENDTARGET_PRIVATE_MOD_EXPRESSION>>)',re.S)
    def lower_private_modulo(match):
        translated=translate_private_modulo('return '+match.group(2))
        if not translated.startswith('return '):
            raise ValueError('private modulo target lowering lost its return wrapper')
        return match.group(1)+'\n'+translated[len('return '):]+'\n'+match.group(3)
    source=private_mod_pattern.sub(lower_private_modulo,source)
    private_expression_pattern = re.compile(
        r'(--<<TARGET_PRIVATE_EXPRESSION>>)(.*?)'
        r'(--<<ENDTARGET_PRIVATE_EXPRESSION>>)',re.S)
    def lower_private_expression(match):
        translated=translate_private_graph('return '+match.group(2))
        if not translated.startswith('return '):
            raise ValueError('private expression target lowering lost its return wrapper')
        return match.group(1)+'\n'+translated[len('return '):]+'\n'+match.group(3)
    source=private_expression_pattern.sub(lower_private_expression,source)
    saved = []
    pattern = re.compile(
        r'--<<TARGET_(?P<name>[A-Z0-9_]+)>>.*?--<<ENDTARGET_(?P=name)>>',
        re.S,
    )
    def stash(match):
        name = match.group('name')
        hook_name = name.removeprefix('51_NATIVE_')
        if hook_name not in _NATIVE_HOOK_NAMES:
            return match.group(0)
        token = f'_KARITY_NATIVE_TARGET_{len(saved)}()'
        saved.append((token, match.group(0)))
        return token
    staged = pattern.sub(stash, source)
    # General translation is retained only for legacy regression probes; the
    # production target always supplies False and emits Lua 5.1 source itself.
    translated = translate(staged, _HELPER) if translate_general else staged
    for token, body in saved:
        if translated.count(token) != 1:
            raise ValueError(f'native target hook placeholder was not preserved: {token}')
        translated = translated.replace(token, body)
    return translated


class Lua51Target:
    lua_version = "5.1"
    user_number_model = "binary64"
    native_graph_control = True
    compact_output_globals = True
    library_dump_normalization = False
    requirements = TargetRequirements({C.GETFENV})
    capabilities = {"native_bitops": False, "env_model": "function", "integer_semantics": "binary64",
                    "loader_api": "loadstring", "unpack_api": "unpack"}

    def runtime_template(self, name):
        if name not in ('vm.lua','classic_exec.lua','mov_exec.lua'):
            raise ValueError(f'unknown runtime template: {name}')
        return (_ROOT.parent/'runtimes'/'lua51'/name).read_text(encoding='utf-8')

    def direct_runtime_entry(self):
        return ('_EX[proto.vm_id+1](proto,{env_box,environment=self_func},'
                '_pack_values(),nil,{})')

    def value_packet_api(self):
        return '_pack_values', '_unpack_values'

    def runtime_entry_symbol(self):
        return '_EX.run'

    def blob_decode_call(self):
        return 'ctx.from_base36(blob)'

    def graph_runtime_options(self):
        return {
            'preserve_native_numbers': True,
            'private_state_native': True,
            'native_graph_control': True,
        }

    def compile(self, script, toolchain=None):
        bytecode = run_tool(script, "compile", toolchain)
        normalize_dump(bytecode)  # Reject non-binary64 or nonstandard compiler ABIs.
        return bytecode

    def build_ir(self, bytecode):
        from ...parser51 import Lua51Parser
        from ..frontends.lua51 import build_semantic_ir
        return build_semantic_ir(Lua51Parser(bytecode).parse())

    @staticmethod
    def _check_native_runtime_api(source):
        """Reject late fragments that bypass the Lua 5.1 generator contract."""
        from ...passes.ts_utils import parse

        context = parse(source)
        forbidden_members = {'math.type', 'table.pack', 'table.unpack'}
        forbidden_calls = {
            '_isC(_pack_values)', '_isC(_unpack_values)',
            'ctx.string.format("%016x",_PX)',
            'ctx.string.format("%016x",_PBH)',
            'string.format("%016x",_PX)',
            'string.format("%016x",_PBH)',
        }
        for node in context.walk():
            expression = context.text(node)
            if ((node.type == 'dot_index_expression' and expression in forbidden_members)
                    or (node.type == 'function_call' and expression in forbidden_calls)):
                nearby = source[max(0, context.cs(node) - 60):context.ce(node) + 61]
                raise ValueError(
                    f'Lua 5.1 runtime generator emitted an unsupported API: '
                    f'{expression} near {nearby!r}'
                )
        return source

    def numeric_blob_decoder(self, source):
        # This expression is inserted after runtime preparation. Emit the
        # native byte storage operation here, before hashing the final function.
        return '''(--<<TARGET_USER_EXPRESSION>>
(function(t)
    local chunks={}
    for i=1,#t do
        local n=t[i]
        chunks[i]=string.char(n%256,math.floor(n/256)%256,
                             math.floor(n/65536)%256,math.floor(n/16777216)%256)
    end
    return string.sub(table.concat(chunks),1,t[0])
end)(blob)
--<<ENDTARGET_USER_EXPRESSION>>
)'''

    def prepare_runtime(self, source, lowered):
        from .runtime_hooks import replace_hook
        # Output passes run before lower_source(). Give the exact-word helper
        # region a version-specific boundary so minification can preserve it
        # only for Lua 5.1 without changing the Lua 5.3 output contract.
        source = source.replace('--<<TARGET_PRIVATE_MIX>>', '--<<TARGET_51_PRIVATE_MIX>>')
        source = source.replace('--<<ENDTARGET_PRIVATE_MIX>>', '--<<ENDTARGET_51_PRIVATE_MIX>>')
        # Output passes may erase target-marker comments before lower_source().
        # Preserve the selected executor contracts on the target instance.
        self._native_classic = '--<<TARGET_CLASSIC_EXEC_NATIVE>>' in source
        source = source.replace('--<<TARGET_MOV_EXEC_NATIVE>>', '')
        self._native_mov_uint = '--<<TARGET_MOV_UINT>>' in source
        if self._native_mov_uint:
            source, count = re.subn(
                r'--<<TARGET_MOV_UINT>>.*?--<<ENDTARGET_MOV_UINT>>',
                'local function _mov_uint(r) return _target_mov_uint(r.u8) end',
                source, flags=re.S,
            )
            if count < 1:
                raise ValueError('MOV uint target hook was not lowered')
        self._private_op_names = ()
        if '--<<TARGET_EXEC_PRIVATE_BINDINGS>>' in source:
            # One shared table keeps exact-state primitives from consuming a
            # separate Lua 5.1 local slot for every helper in each executor.
            names = ('_pint', '_pword', '_peq', '_plow', '_pmod', '_padd',
                     '_pneg', '_psub', '_pmul', '_pband', '_pxor', '_pbor',
                     '_pnot', '_pshl', '_pshr', '_pmix', '_pmul64', '_pand_limb', '_por_limb',
                     '_pmul_low', '_plow_shift')
            bank = 'local _private_ops={' + ','.join(names) + '}\n'
            source = source.replace('--<<ENDTARGET_51_PRIVATE_MIX>>',
                                    bank + '--<<ENDTARGET_51_PRIVATE_MIX>>', 1)
            source = replace_hook(
                source, 'EXEC_PRIVATE_BINDINGS', 'local _private_ops=_private_ops',
            )
            self._private_op_names = names
        if lowered.backend in ("classic", "mov"):
            environment_source = (
                "local function _source_environments(upvals,parents) "
                "local result={upvals.environment};for i=1,#(parents or {}) do "
                "result[#result+1]=parents[i] end;return result end\n"
            )
        else:
            environment_source = (
                "local function _source_environments(upvals,frame) "
                "local result={upvals.environment};while frame do "
                "local parent=frame[__VM_FR_UPVALS__];"
                "result[#result+1]=parent.environment;"
                "frame=frame[__VM_FR_PARENT__] end;return result end\n"
            )
        source_call = (
            "local function _source_call(fn,upvals,frame,...) "
            "if fn~=_native_getfenv and fn~=_native_setfenv then return fn(...) end;"
            "local environments=_source_environments(upvals,frame);"
            "local subject,value=...;"
            "local level=subject==nil and 1 or _native_tonumber(subject);"
            "if level then level=level<0 and _native_math_ceil(level) or _native_math_floor(level) end;"
            "if level and level>0 then local environment=environments[level];"
            "if environment then if fn==_native_getfenv then return _native_getfenv(environment) end;"
            "return _native_setfenv(environment,value) end;"
            "_native_error('invalid level',0) end;return fn(...) end\n"
        )
        source=source.replace(
            "local function _source_value(v)",
            environment_source
            + source_call
            + "local function _source_value(v)",
        )
        source=self._check_native_runtime_api(source)
        if self._native_classic:
            # Private-state expressions must be lowered before optional output
            # passes erase the comment markers that delimit their exact-word
            # contract. The helper still leaves all target-native blocks as
            # authored; it never runs the generic source translator here.
            source = _translate_preserving_native_hooks(source, translate_general=False)
        return source

    def apply_keystream(self, source):
        from ..vm_variants import apply_keystream
        k1=random.randrange(1,0x100000000)|1
        k2=random.randrange(1,0x100000000)|1
        k3=random.randrange(1,0x100000000)|1
        s1=random.randint(11,23)
        s2=random.randint(7,17)
        mode=random.randrange(2)
        def render():
            tail=(f"x=(x+_imul48(i,{k3}))%281474976710656.0"
                  if mode==0 else
                  f"x=_ixor(_ixor(x,_imul48(_ikey48(_ksd),{k3})),_ishr48(x,{random.randint(9,21)}))")
            return f'''--<<TARGET_INSTRUCTION_KEYSTREAM>>
local function _imul48(a,b)
    local a0,b0=a%16777216,b%16777216
    local a1,b1=math.floor(a/16777216),math.floor(b/16777216)
    local product=a0*b0
    local lo=product%16777216
    local hi=(math.floor(product/16777216)+a0*b1+a1*b0)%16777216
    return lo+hi*16777216
end
local function _ishl48(a,n)
    if n>=48 then return 0 end
    return (a%2^(48-n))*2^n
end
local function _ishr48(a,n) return math.floor(a/2^n) end
local function _ksm(i)
    i=_ikey48(i)
    local x=_imul48(i,{k1})
    x=_ixor(x,_imul48(_ikey48(_ksd),{k2}))
    x=_ixor(_ixor(x,_ishr48(x,{s1})),_ishl48(i,{s2}))
    {tail}
    return x
end
--<<ENDTARGET_INSTRUCTION_KEYSTREAM>>'''
        def render_strings():
            k1=random.randrange(1,256)|1
            k2=random.randrange(0,256)
            s1=random.randint(2,5)
            return f'''--<<TARGET_STRING_KEYSTREAM>>
local function _kss(s)
    local out={{}}
    for i=1,#s do
        local m=_ixor(_ixor((i%256)*{k1},_ikey48(_ksd)),math.floor(i/2^{s1}))
        m=_ixor(m,{k2})%256
        out[i]=_ixor(string.byte(s,i),m)%256
    end
    local chunks={{}}
    for i=1,#out,4096 do
        local last=i+4095;if last>#out then last=#out end
        chunks[#chunks+1]=string.char(_unpack_values(out,i,last))
    end
    return table.concat(chunks)
end
--<<ENDTARGET_STRING_KEYSTREAM>>'''
        return apply_keystream(source, render_ksm=render, render_kss=render_strings)

    def apply_tamper(self, source):
        from ..vm_variants import apply_tamper, _TAMPER_ALWAYS, _TAMPER_C_POOL
        def render():
            lines = ['--<<TARGET_TAMPER>>',
                     'local _hk,_hm,_hc=debug.gethook()', 'local _t=0']
            def weight():
                return random.randint(1,0x3FFF)
            hook_checks = [
                f'if _hk~=nil then _t=_t+{weight()} end',
                f'if _hm and #_hm>0 then _t=_t+{weight()} end',
                f'if _hc and _hc~=0 then _t=_t+{weight()} end',
            ]
            random.shuffle(hook_checks)
            lines.extend(hook_checks)
            lines.append('local function _isC(f) local ok,info=pcall(debug.getinfo,f,"S") '
                         'return ok and info~=nil and info.what=="C" end')
            pool = [fn for fn in dict.fromkeys(_TAMPER_C_POOL)
                    if fn not in _TAMPER_ALWAYS]
            random.shuffle(pool)
            functions = list(_TAMPER_ALWAYS) + pool[:random.randint(3,7)]
            random.shuffle(functions)
            # The shared pool names Lua 5.3 APIs. Select stock Lua 5.1 C
            # functions before emitting this late fragment; the Lua helpers
            # _pack_values/_unpack_values themselves are not C functions.
            native_c_functions = {
                'table.pack': '_native_select',
                'table.unpack': '_native_unpack',
            }
            lines.extend(f'if not _isC({fn}) then _t=_t+{weight()} end'
                         for fn in (native_c_functions.get(name, name)
                                    for name in functions))
            k1=random.randrange(1,0x100000000)|1
            mixes = [
                f'_imul32(_t,{k1})',
                f'_ixor(_imul32(_t,{k1}),(_t*2^{random.randint(1,13)})%4294967296)',
                f'(_imul32(_t,{k1})+_imul32(_t,{random.randrange(1,0x100000000)|1}))%4294967296',
            ]
            lines.append(f'crc=_ixor(crc,{random.choice(mixes)})%4294967296')
            lines.append('--<<ENDTARGET_TAMPER>>')
            return '\n    '.join(lines)
        return apply_tamper(source,renderer=render)

    def finalize_runtime(self, source):
        # Execution-kit and fused-handler variants inline instruction field
        # extraction after prepare_runtime(). At this point the randomized
        # layout tokens are concrete, so lower only known instruction-word
        # locals without changing ordinary 32-bit state expressions.
        source=self._check_native_runtime_api(source)
        shifted = re.compile(r'\((?P<value>_dw|_ei|ei)>>(?P<shift>\d+)\)&0x(?P<mask>[0-9A-Fa-f]+)')
        def field(match):
            width=int(match.group('mask'),16)+1
            return f"_ifield48({match.group('value')},{match.group('shift')},{width})"
        source=shifted.sub(field,source)
        source=re.sub(r'(?<![A-Za-z0-9_])(?P<value>_dw|_ei|ei)&0x7F',
                      lambda match: f"_ifield48({match.group('value')},0,128)",source)
        # Handler graphs are emitted after ``prepare_runtime``.  Lower their
        # explicitly typed private-word regions now, before output passes can
        # erase the boundaries. All three backend assets are target-native;
        # this step deliberately leaves general user expressions untouched.
        source = _translate_preserving_native_hooks(source, translate_general=False)
        names = getattr(self, '_private_op_names', ())
        if names:
            from ...passes.ts_utils import parse
            ctx = parse(source)
            replacements = []
            signature = re.compile(
                r'^function\s*\(\s*proto\s*,\s*upvals\s*,\s*args\s*,\s*va_in\b'
            )
            for node in ctx.walk():
                if node.type != 'function_definition':
                    continue
                body = ctx.text(node)
                if not signature.match(body.lstrip()):
                    continue
                for index, name in enumerate(names, 1):
                    body = re.sub(
                        rf'(?<![\w.]){re.escape(name)}\b',
                        f'_private_ops[{index}]', body,
                    )
                replacements.append((ctx.cs(node), ctx.ce(node) + 1, body))
            for start, end, body in sorted(replacements, reverse=True):
                source = source[:start] + body + source[end:]
        return _promote_native_hook_markers(source)

    def lower_source(self, source):
        source = _replace_lua_nodes(source, {'identifier': _NATIVE_ALIASES})
        prelude = (
            "local math,string,table,debug,type,tostring,tonumber,select,error,"
            "rawget,rawset,getfenv,setfenv,unpack="
            "math,string,table,debug,type,tostring,tonumber,select,error,"
            "rawget,rawset,getfenv,setfenv,unpack\n"
        )
        # Native API references share one capture, even when an executor's
        # nested helpers use many C functions. This bank stores the original
        # functions/libraries directly; it adds no wrapper or value dispatcher.
        # Keep it distinct from _ENV, which may be shadowed for source globals.
        prelude += (
            "local _native_api={math=math,string=string,table=table,debug=debug,"
            "type=type,tostring=tostring,tonumber=tonumber,select=select,error=error,"
            "rawget=rawget,rawset=rawset,getfenv=getfenv,setfenv=setfenv,unpack=unpack}\n"
        )
        if getattr(self, '_native_mov_uint', False):
            prelude += '''local function _target_mov_uint(read_u8)
    local value,shift=0,0
    for i=1,5 do
        local b=read_u8()
        if i==5 and b>15 then error("MOV field overflow") end
        value=value+(b%128)*2^shift
        if b<128 then return value end
        shift=shift+7
    end
    error("invalid MOV field")
end
'''
        # All three backend assets own their exact-state operations. No
        # generated runtime embeds the generic int64/shim modules or passes
        # through whole-source arithmetic translation.
        prelude += ("local _ENV=setmetatable({math=math,string=string,table=table,"
                    "type=type,tostring=tostring,tonumber=tonumber,select=select,error=error,"
                    "rawget=rawget,rawset=rawset,debug=debug,getfenv=getfenv},{__index=_G})\n")
        translated = _translate_preserving_native_hooks(source, translate_general=False)
        translated = re.sub(
            r'--<<(?:END)?TARGET_51_NATIVE_[A-Z0-9_]+>>[ \t]*(?:\r?\n)?',
            ' ', translated,
        )
        for marker in ('TARGET_51_PRIVATE_MIX', 'ENDTARGET_51_PRIVATE_MIX',
                       'TARGET_51_MOV_NATIVE', 'ENDTARGET_51_MOV_NATIVE'):
            translated = re.sub(
                r'--<<' + marker + r'>>[ \t]*(?:\r?\n)?', ' ', translated,
            )
        anchor = re.match(r"return\s+function\s*\([^)]*\)", translated)
        if anchor:
            # Include the integer/API/dump helpers in the self-hashed function.
            prelude += "\n--[[TARGET51_PRELUDE_END]]\n"
            return _compact_executor_captures(
                translated[:anchor.end()] + "\n" + prelude + translated[anchor.end():])
        return _compact_executor_captures(prelude + translated)

    def bind_lines(self, source, context):
        from ..vm_variants import apply_line_state
        # The late line-state fragment is private 32-bit state, not user-value
        # arithmetic. Emit it in the target-native binary64 domain for every
        # backend so bind_lines never needs the whole-source compatibility
        # translator after backend emission.
        result, state, lines = apply_line_state(source, "",
                                               output_passes=(), insertion_anchor="--[[TARGET51_PRELUDE_END]]",
                                               native_u32=True)
        return result.replace("--[[TARGET51_PRELUDE_END]]", ""), state, lines

    def dump_function(self, source, header, decoy_name, decoy_value, toolchain):
        return normalize_dump(run_tool(source, "dump", toolchain))

    def wrap(self, source, decoy_name, decoy_value, vm_name, blob, tail):
        if not source.startswith("return "):
            raise ValueError("Lua 5.1 VM source must return its runtime function")
        body = source[len("return "):]
        # The lowered body is already native Lua 5.1 source. Emitting it as a
        # function literal preserves the same nested prototype used for the
        # normalized integrity dump, without serializing the whole runtime into
        # a decimal-escaped string and reparsing it through loadstring.
        return (f'local {decoy_name}="{decoy_value}";local {vm_name}={body};'
                f'setfenv({vm_name},getfenv(1));'
                f'return ({vm_name}(1032,413,258,104,953,283,120))({blob},"{tail}",{vm_name})')
