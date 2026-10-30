"""Lower semantic instructions to program-specific Lua statements."""
import math
import random
import time
from collections import Counter

from .bare_dispatch import emit as emit_dispatch


def literal(value):
    if value is None: return 'nil'
    if value is True: return 'true'
    if value is False: return 'false'
    if isinstance(value, (bytes, str)):
        from ...passes.string_mosaic import lua_string
        return lua_string(value)
    if isinstance(value, float):
        if math.isnan(value): return '(0/0)'
        if math.isinf(value): return '(-1/0)' if value < 0 else '(1/0)'
        return repr(value)
    if value == -(1 << 63): return '(-9223372036854775807-1)'
    return str(value)


_BINARY = {'ADD': '+', 'SUB': '-', 'MUL': '*', 'MOD': '%', 'POW': '^',
           'DIV': '/', 'FLOOR_DIV': '//', 'BIT_AND': '&', 'BIT_OR': '|',
           'BIT_XOR': '~', 'SHIFT_LEFT': '<<', 'SHIFT_RIGHT': '>>'}
_UNARY = {'NEGATE': '-', 'BIT_NOT': '~', 'LOGICAL_NOT': 'not ', 'LENGTH': '#'}


class Program:
    def __init__(self, lowered, context):
        self.lowered, self.context = lowered, context
        self.version = context.target.lua_version
        self.security = lowered.backend_data['source_protection']
        self.functions = list(lowered.backend_data['bare_emission_ir'].functions())
        self.optimization = Counter(lowered.backend_data['optimization'])
        self.frame_plans = []
        self.flow_plans = []
        self.validation_bytes = 0
        slots=random.sample(range(31,2**24),len(self.functions))
        self.factory_slots=tuple(slots)
        self.factory_ids={f.id:slot for f,slot in zip(self.functions,slots)}
        retired={self.functions[0].id}|{f.id for f in self.functions if f.debug_metadata.get('security_owned')}
        self.retired_factory_slots=tuple(self.factory_ids[key] for key in sorted(retired))
        for function in self.functions:
            if function.debug_metadata.get('security_owned'):continue
            for block in function.blocks:
                for instruction in block.instructions:
                    if instruction.operation=='CLOSURE':
                        child=next(o.value for o in instruction.operands if o.role=='child')
                        if function.children[child].id in retired:
                            raise ValueError('guest closure refers to a consumed bootstrap factory')
        self.factories = {f.id: '_BF[' + str(slot) + ']' for f,slot in zip(self.functions,slots)}
        self.helpers = {}
        self.shared_helpers = {}
        self.tailcalls = any(i.operation=='TAIL_CALL' for f in self.functions for b in f.blocks for i in b.instructions)
        self.counter = 0
        self.poisoned = any(i.operation == 'VM_PANIC' for f in self.functions
                            for b in f.blocks for i in b.instructions)

    def name(self, kind):
        self.counter += 1
        return '_B' + kind + str(self.counter)

    def api(self, key):
        aliases = {'unpack': 'unpack' if self.version == '5.1' else 'table.unpack'}
        value = aliases.get(key, key)
        name = '_BA_' + key.replace('.', '_')
        self.helpers[name] = 'local ' + name + '=' + value + '\n'
        return name

    def source(self):
        definitions = []
        for function in reversed(self.functions):
            definition=Function(self, function).source()
            definitions.append(definition)
            if function.debug_metadata.get('security_subsystem')=='runtime_validation':
                self.validation_bytes+=len(definition.encode())
        prefix = 'local _BE=_ENV_GUEST\nlocal _BN=_ENV_NATIVE\n--<<BARE_NATIVE_CAPTURE>>\n'
        if self.poisoned: prefix += 'local _BP=false\n'
        root = self.functions[0]
        forward_args = any(i.operation in ('VARARG', 'PACK_VARARG') for b in root.blocks for i in b.instructions)
        context_up=root.debug_metadata['security_context_upvalue']
        guard_up=root.debug_metadata['security_guard_upvalue']
        upvalues = ['{_Bsecurity}' if i==context_up else '{_Bguard}' if i==guard_up else
                    '{_BE}' if i == 0 and self.version == '5.3' else '{}' for i in
                    range(sum(v.kind == 'upvalue' for v in root.values))]
        checked_return = ('local function _Bchecked(...) if _BP then ' + self.api('error') + '(nil,0) end;return ... end\n') if self.poisoned else ''
        from ..runtime_identity import primitive_source
        primitives=primitive_source(self.version,library_dump=bool(self.context.toolchain.lua_library),tailcalls=self.tailcalls)
        if 'setmeta' in self.security.features:primitives+=('local _Bsetmeta=setmetatable\nlocal function _Bchoose(s,fn) '
            'if fn==_Bsetmeta then return s['+str(self.security.slots['setmeta'])+'] end;return fn end\n')
        security_root=next(f for f in self.functions if f.id==self.security.runtime_id)
        security_upvalues=['{_BE}' for v in security_root.values if v.kind=='upvalue']
        values=('_BE','rawget','type','error','next','debug.getmetatable','_Bdump','_Bcrc','_Bxor','_Bmul','_BN','_ENV_CHECK','_ENV_REFRESH','_BF')
        fields=[f'[{self.security.bootstrap_slots[i]}]={value}' for i,value in enumerate(values,1)
                if f'P[{self.security.bootstrap_slots[i]}]' in self.security.native_source]
        random.shuffle(fields)
        initialize=(f'local _Bsecurity=({self.factories[security_root.id]}({{{",".join(security_upvalues)}}}))()'
            '(_Bmake,{'+','.join(fields)+'},_Bself,_Bpayload,_LS)\n'
            f'local _Bguard=_Bsecurity[{self.security.slots["guard"]}]\n')
        factory_slots='{'+','.join(map(str,self.factory_slots))+'}'
        native=self.security.native_source.replace('__FACTORY_SLOTS__',factory_slots)
        native=native.replace('__FACTORY_RETIRED__','{'+','.join(
            '['+str(slot)+']=true' for slot in self.retired_factory_slots)+'}')
        return ('return function(_Bself,_Bpayload,...)\n' + prefix + ''.join(self.helpers.values()) + checked_return + primitives +
                ''.join(self.shared_helpers.values())+'local _Bmake='+native+'\n'+
                'local _BF={}\n' + ''.join(definitions) +
                'local _Broot_factory='+self.factories[root.id]+'\n'+
                initialize+'return (_Broot_factory({' + ','.join(upvalues) + '}))(' + ('...' if forward_args else '') + ')\nend')


class Function:
    def __init__(self, program, function):
        self.program, self.function = program, function
        self.outer_locals = set()
        self.scratch_base=function.debug_metadata.get('security_scratch_base')
        self.original_stack=self.scratch_base if self.scratch_base is not None else function.max_stack_size
        self.constants = {v.index: v.literal for v in function.values if v.kind == 'constant'}
        self.captured = {o.value for b in function.blocks for i in b.instructions
                         if i.operation == 'CLOSURE' for o in i.operands
                         if o.role == 'capture' and o.kind == 'register'}
        self.open = any(o.kind == 'register_range' and o.count is None
                        for b in function.blocks for i in b.instructions for o in i.operands)
        # A native tail-entry wrapper moves wide parameter lists into a frame
        # table before the body starts. Its old argument frame then disappears,
        # preserving GC lifetimes without exhausting Lua's local budget.
        self.wide = function.params >= 128
        dynamic_starts = [o.value for b in function.blocks for i in b.instructions for o in i.operands
                          if o.kind == 'register_range' and (o.count is None or o.count > 32)]
        self.dynamic = bool(dynamic_starts)
        self.dynamic_start = min(dynamic_starts, default=self.original_stack)
        from .bare_registers import native_prefix
        self.local_count = native_prefix(function)
        self.initial_local_count = self.local_count
        self.uses_scratch = False
        self.support = set()
        self.conditions = {}
        self.liveness = program.lowered.backend_data['liveness'][function.id]
        self.facts = program.lowered.backend_data['bare_facts'][function.id]
        from .bare_registers import allocate
        self.register_map = allocate(self)
        self.local_slots = tuple(sorted(set(self.register_map.values())))
        self.uses_spill = self.dynamic or self.local_count < self.original_stack
        self.local_releases=program.lowered.backend_data['bare_local_releases'][function.id]
        self.edge_releases=program.lowered.backend_data['bare_edge_releases'][function.id]
        self.blocks_by_id={b.id:b for b in function.blocks}
        from .bare_expressions import prepare
        prepare(self)

    def name(self, kind): return self.program.name(kind)
    def api(self, key): return self.program.api(key)

    def slot(self, index):
        if self.scratch_base is not None and index>=self.scratch_base:
            self.uses_scratch = True
            return '_BX['+str(index-self.scratch_base)+']'
        return '_Br' + str(self.physical(index)) if index < self.local_count else '_BS[' + str(index) + ']'

    def physical(self, index):
        return self.register_map.get(index,index)

    def r(self, index):
        result = self.slot(index)
        return result + '[1]' if index in self.captured else result

    def operand(self, operand):
        if operand.kind == 'constant': return literal(self.constants[operand.value])
        if operand.kind == 'register': return self.r(operand.value)
        if operand.kind == 'upvalue': return '_BU[' + str(operand.value + 1) + '][1]'
        return literal(operand.value)

    def span(self, operand):
        if operand.count is None:
            # The open tail is private spill storage. Captured cells live in
            # separate tables and require the original _Bg snapshot path.
            if operand.value>=self.local_count and not any(i>=operand.value for i in self.captured):
                self.program.optimization['dynamic_value_copies_elided'] += 1
                return self.api('unpack')+'(_BS,'+str(operand.value)+',_BT)'
            self.support.add('values')
            return '_Bvalues(' + str(operand.value) + ',_BT-' + str(operand.value) + '+1)'
        return ','.join(self.r(i) for i in range(operand.value, operand.value + operand.count))

    def store(self, operand, expression):
        if operand.count is None:
            self.support.add('store')
            return '_Bstore(' + str(operand.value) + (',' + expression if expression else '') + ')\n'
        if operand.count == 0:
            return expression + '\n' if expression else ''
        if operand.count > 32:
            self.support.add('fixed')
            return '_Bfixed(' + str(operand.value) + ',' + str(operand.count) + ',' + expression + ')\n'
        return self.span(operand) + '=' + expression + '\n'

    def close(self, first):
        if first is None: return ''
        return ''.join(self.slot(i) + '={' + self.r(i) + '}\n' +
                       ('_BC[' + str(i) + ']=' + self.slot(i) + '\n' if self.dynamic and i>=self.local_count else '')
                       for i in sorted(self.captured) if i >= first)

    def source(self):
        body = emit_dispatch(self.function, self)
        params = ['_Bp' + str(i) for i in range(self.function.params)]
        signature = ','.join(params + (['...'] if self.function.vararg else []))
        init = []
        if self.program.poisoned: init.append('if _BP then ' + self.api('error') + '(nil,0) end\n')
        locals_ = ['_Br'+str(i) for i in self.local_slots] + sorted(self.outer_locals)
        if self.uses_spill and not self.wide: locals_.append('_BS')
        if self.open: locals_.append('_BT')
        if self.uses_scratch:locals_.append('_BX')
        if (1 if self.wide else len(params)) + len(locals_) > 190:
            raise ValueError('Bare function exceeds the native Lua local-variable budget')
        if locals_: init.append('local ' + ','.join(locals_) + '\n')
        if self.uses_spill and not self.wide: init.append('_BS={}\n')
        if self.open: init.append('_BT=-1\n')
        if self.uses_scratch:init.append('_BX={}\n')
        elif self.scratch_base is not None:self.program.optimization['scratch_tables_elided'] += 1
        for i in sorted(self.captured):
            init.append(self.slot(i) + '={' + (self.slot(i) if self.wide and i < self.function.params else '') + '}\n')
        if not self.wide:
            for i, param in enumerate(params): init.append(self.r(i) + '=' + param + '\n' + param + '=nil\n')
        init.append(self.helpers())
        if self.dynamic and self.local_count:self.program.optimization['dynamic_prefix_locals'] += len(self.local_slots)
        self.program.frame_plans.append({'function':self.function.id,'locals':len(self.local_slots),
            'local_prefix':self.local_count,'initial_prefix':self.initial_local_count,
            'local_budget':getattr(self,'native_budget',None),'register_map':tuple(sorted(self.register_map.items())),
            'dynamic':self.dynamic,'dynamic_start':self.dynamic_start,'scratch':self.uses_scratch,
            'wide':self.wide,'spill':self.uses_spill,'original_stack':self.original_stack})
        name = self.program.factories[self.function.id]
        register='_Bregister' if self.program.tailcalls else ''
        if self.wide:
            packet = '{' + ','.join('[' + str(i) + ']=' + param for i, param in enumerate(params)) + '}'
            env = (self.api('setfenv') + '(_Bwide,' + self.api('getfenv') + '(1))\n') if self.program.version == '5.1' else ''
            return (name + '=function(_BU)\nlocal function _Bwide(_BS' + (',...' if self.function.vararg else '') + ')\n'
                    + ''.join(init) + body + 'end\nreturn '+register+'(function(' + signature + ')\n' + env
                    + 'return _Bwide(' + packet + (',...' if self.function.vararg else '') + ')\nend)\nend\n')
        return name + '=function(_BU)\nreturn '+register+'(function(' + signature + ')\n' + ''.join(init) + body + 'end)\nend\n'

    def helpers(self):
        result = ''
        if self.dynamic:
            # Dynamic open result ranges share the same cells as static reads.
            cells = sorted(i for i in self.captured if i>=self.local_count)
            if cells:
                cell_entries = ','.join('[' + str(i) + ']=' + self.slot(i) for i in cells)
                result += 'local _BC={' + cell_entries + '}\n'
                result += 'local function _Bg(i) local c=_BC[i];if c then return c[1] end;return _BS[i] end\n'
                result += 'local function _Bs(i,v) local c=_BC[i];if c then c[1]=v else _BS[i]=v end end\n'
            else:
                self.program.optimization['cell_tables_elided'] += 1
                result += 'local function _Bg(i) return _BS[i] end\n'
                result += 'local function _Bs(i,v) _BS[i]=v end\n'
        if 'fixed' in self.support:
            result += ('local function _Bfixed(a,n,...) for i=1,n do _Bs(a+i-1,'
                       + self.api('select') + '(i,...)) end end\n')
        if 'values' in self.support:
            result += ('local function _Bvalues(a,n) local t={} for i=1,n do t[i]=_Bg(a+i-1) end;return '
                       + self.api('unpack') + '(t,1,n) end\n')
        if 'store' in self.support:
            result += ('local function _Bstore(a,...) local n=' + self.api('select') + '("#",...);'
                       'for i=1,n do _Bs(a+i-1,' + self.api('select') + '(i,...)) end;'
                       'for i=a+n,_BT do _Bs(i,nil) end;_BT=a+n-1 end\n')
        if 'for' in self.support:
            # FORPREP conversions are shared with Classic. The dispatcher
            # executes FOR_LOOP updates directly in their program block.
            if self.program.version == '5.1':
                self.program.shared_helpers['for']=('local function _for_values(a,b,c) for i=a,b,c do break end;return '
                                 + self.api('tonumber') + '(a),' + self.api('tonumber') + '(b),'
                                 + self.api('tonumber') + '(c) end\n')
                return result
            from pathlib import Path
            path = Path(__file__).resolve().parents[1] / 'runtimes' / 'classic_exec.lua'
            text = path.read_text(encoding='utf8')
            fragment = text[text.index('local function _for_fault'):text.index('--<<EXEC>>')]
            import re
            apis=('tonumber','math.type','math.floor','math.ceil','math.tointeger','math.mininteger','math.maxinteger')
            fragment=re.sub(r'local _for_api=\{[^\n]+\}\n','',fragment)
            for index,api in enumerate(apis,1):fragment=fragment.replace('_for_api['+str(index)+']',self.api(api))
            self.program.shared_helpers['for']=fragment
        return result

    def condition(self, block): return self.conditions[block.id]

    def clear(self, indices, live=()):
        # Keep reference releases at their original instruction boundary.
        prefix=self.function.id+':r'
        owners={self.physical(int(key[len(prefix):])) for key in live
                if key.startswith(prefix) and key[len(prefix):].isdigit() and int(key[len(prefix):])<self.local_count}
        filtered=[];seen=set()
        for i in indices:
            if i<self.local_count and self.physical(i) in owners:continue
            key=('local',self.physical(i)) if i<self.local_count else ('indexed',i)
            if key not in seen:filtered.append(i);seen.add(key)
        indices=filtered
        return ''.join(','.join(self.r(i) for i in indices[first:first+24])+'='+
                       ','.join('nil' for _ in indices[first:first+24])+'\n'
                       for first in range(0,len(indices),24))

    def instructions(self, instructions, block):
        from .bare_statements import emit
        return emit(self, instructions, block)

    def dead_indices(self, ins):
        dead=(set(ins.inputs)|set(ins.outputs))-self.liveness.after[ins.id]
        prefix=self.function.id+':r'
        result={int(key[len(prefix):]) for key in dead if key.startswith(prefix) and key[len(prefix):].isdigit()}
        return sorted(result|set(self.local_releases.get(ins.id,())))

    def edge_clear(self, block, target):
        return self.clear(self.edge_releases.get((block.id,target),()),
            self.liveness.before[self.blocks_by_id[target].instructions[0].id])

    def coalesced_copy(self, ins):
        if ins.operation!='MOVE' or 'protection_origin' in ins.metadata or self.program.poisoned:return None
        fields={o.role:o.value for o in ins.operands}
        a,b=fields['source'],fields['destination']
        if a>=self.local_count or b>=self.local_count or a in self.captured or b in self.captured:return None
        if self.physical(a)!=self.physical(b):return None
        self.program.optimization['copies_elided'] += 1
        return self.clear(self.dead_indices(ins),self.liveness.after[ins.id])

    def instruction(self, ins, block):
        if ins.metadata.get('bare_call_skip'):return ''
        compact=ins.metadata.get('bare_call')
        if compact:
            if compact[0]=='guard':
                index=self.function.debug_metadata['security_guard_upvalue']
                end=ins.metadata['bare_call_end']
                return ('_BU['+str(index+1)+'][1]('+literal(compact[1])+')\n'+
                        self.clear(self.local_releases.get(end,()),self.liveness.after[end]))
            from ..ir.model import IROperand
            _,name,args,result=compact
            context=self.function.debug_metadata['security_context_upvalue']
            expression=('_BU['+str(context+1)+'][1]['+str(self.program.security.slots[name])+']('
                +','.join(self.operand(IROperand('value',kind,value)) for kind,value in args)+')')
            code=(self.r(result)+'=' if result is not None else '')+expression+'\n'
            after=self.liveness.after[ins.metadata['bare_call_end']]
            dead=sorted({value for kind,value in args if kind=='register'
                         and f'{self.function.id}:r{value}' not in after})
            if dead:code+=self.clear(dead,after)
            # The compact group executes all of its logical instructions at
            # once, including any lexical-scope release at the group end.
            expired=self.local_releases.get(ins.metadata['bare_call_end'],())
            if expired:code+=self.clear(expired,after)
            return code
        fields = {o.role: o for o in ins.operands if o.role != 'capture'}
        op = ins.operation
        v = lambda role: self.operand(fields[role])
        dest = lambda expression: v('destination') + '=' + expression + '\n'
        code = ''
        if op == 'MOVE': code = dest(v('source'))
        elif op == 'LOAD_CONST': code = dest(v('value'))
        elif op == 'LOAD_BOOL': code = dest(v('value'))
        elif op == 'LOAD_NIL':
            span = fields['destination']
            code = ''.join(self.r(i)+'=nil\n' for i in range(span.value,span.value+span.count))
        elif op == 'GET_UPVALUE': code = dest(v('source'))
        elif op in ('GET_UPVALUE_TABLE', 'GET_TABLE'): code = dest('(' + v('table') + ')[' + v('key') + ']')
        elif op in ('SET_UPVALUE_TABLE', 'SET_TABLE'): code = v('table') + '[' + v('key') + ']=' + v('value') + '\n'
        elif op == 'SET_UPVALUE': code = v('destination') + '=' + v('source') + '\n'
        elif op in ('GLOBAL_GET', 'GLOBAL_SET'):
            env = self.api('getfenv') + '(1)' if self.program.version == '5.1' else '_BE'
            ref = env + '[' + v('key') + ']'
            code = dest(ref) if op == 'GLOBAL_GET' else ref + '=' + v('source') + '\n'
        elif op == 'NEW_TABLE': code = dest('{}')
        elif op == 'SELF':
            a = fields['destination'].value
            code = self.r(a + 1) + '=' + v('receiver') + '\n' + self.r(a) + '=(' + v('receiver') + ')[' + v('key') + ']\n'
        elif op in _BINARY: code = dest('(' + v('left') + ')' + _BINARY[op] + '(' + v('right') + ')')
        elif op in _UNARY: code = dest(_UNARY[op] + '(' + v('source') + ')')
        elif op == 'CONCAT':
            span = fields['sources']; code = dest('..'.join('(' + self.r(i) + ')' for i in range(span.value, span.value + span.count)))
        elif op == 'JUMP': code = self.close(fields['close_from'].value)
        elif op in ('EQUAL', 'LESS_THAN', 'LESS_EQUAL', 'TEST', 'TEST_SET'):
            if op in ('TEST', 'TEST_SET'): condition = '(not not (' + v('condition') + '))'
            else: condition = '(' + v('left') + ({'EQUAL': '==', 'LESS_THAN': '<', 'LESS_EQUAL': '<='}[op]) + v('right') + ')'
            condition = '(' + condition + '==' + v('expected') + ')'
            if op == 'TEST_SET': code = 'if ' + condition + ' then ' + dest(v('condition')) + 'end\n'
            self.conditions[block.id] = condition
        elif op in ('CALL', 'TAIL_CALL'):
            callee=v('callee')
            if self.scratch_base is not None and 'setmeta' in self.program.security.features:
                context=self.function.debug_metadata['security_context_upvalue']
                callee='_Bchoose(_BU['+str(context+1)+'][1],'+callee+')'
            call = callee + '(' + self.span(fields['arguments']) + ')'
            if op == 'TAIL_CALL' and self.program.poisoned: call = '_Bchecked(' + call + ')'
            if op == 'TAIL_CALL' and self.scratch_base is not None:
                guard=self.function.debug_metadata['security_guard_upvalue']
                args=self.span(fields['arguments'])
                call='_Broute(_BU['+str(guard+1)+'][1],'+callee+(','+args if args else '')+')'
            code = 'do return ' + call + ' end\n' if op == 'TAIL_CALL' else self.store(fields['results'], call)
        elif op == 'RETURN': code = 'do return ' + self.span(fields['values']) + ' end\n'
        elif op == 'FOR_PREP':
            self.support.add('for'); a = fields['loop_state'].value
            names = ','.join(self.r(a + j) for j in range(3))
            code = names + '=_for_values(' + names + ')\n' + self.r(a) + '=' + self.r(a) + '-' + self.r(a + 2) + '\n'
        elif op == 'FOR_LOOP':
            a = fields['loop_state'].value
            code = self.r(a) + '=' + self.r(a) + '+' + self.r(a + 2) + '\n'
            condition = '((' + self.r(a + 2) + '>0 and ' + self.r(a) + '<=' + self.r(a + 1) + ') or (' + self.r(a + 2) + '<=0 and ' + self.r(a) + '>=' + self.r(a + 1) + '))'
            code += 'if ' + condition + ' then ' + self.r(fields['iteration'].value) + '=' + self.r(a) + ' end\n'
            self.conditions[block.id] = condition
        elif op == 'ITER_CALL':
            a = fields['iterator'].value
            code = self.store(fields['results'], '(' + self.r(a) + ')(' + self.r(a + 1) + ',' + self.r(a + 2) + ')')
        elif op == 'ITER_LOOP':
            condition = '(' + v('result') + '~=nil)'
            code = 'if ' + condition + ' then ' + v('control') + '=' + v('result') + ' end\n'
            self.conditions[block.id] = condition
        elif op == 'SET_LIST':
            span = fields['values']; base = (fields['batch'].value - 1) * 50
            if span.count is None:
                index = self.name('list')
                code = 'for ' + index + '=1,_BT-' + str(span.value) + '+1 do ' + v('table') + '[' + str(base) + '+' + index + ']=_Bg(' + str(span.value - 1) + '+' + index + ') end\n'
            else:
                code = ''.join(v('table') + '[' + str(base + j + 1) + ']=' + self.r(span.value + j) + '\n' for j in range(span.count))
        elif op == 'CLOSURE':
            child = self.function.children[fields['child'].value]
            refs = [self.slot(o.value) if o.kind == 'register' else '_BU[' + str(o.value + 1) + ']'
                    for o in ins.operands if o.role == 'capture']
            expression = self.program.factories[child.id] + '({' + ','.join(refs) + '})'
            if self.program.version == '5.1': expression = self.api('setfenv') + '(' + expression + ',' + self.api('getfenv') + '(1))'
            code = dest(expression)
        elif op == 'VARARG': code = self.store(fields['results'], '...')
        elif op == 'PACK_VARARG': code = dest('{n=' + self.api('select') + '("#",...),...}')
        elif op.startswith('GET_') and op in ('GET_SCRIPT_HASH', 'GET_VM_COUNT', 'GET_VM_ID', 'GET_LAYOUT', 'GET_CODE_LENGTH'):
            number = {'GET_SCRIPT_HASH': int(self.program.lowered.semantic_ir.generation[:8], 16),
                      'GET_LAYOUT': int(self.program.lowered.semantic_ir.generation[8:16], 16),
                      'GET_VM_COUNT': 1, 'GET_VM_ID': 0,
                      'GET_CODE_LENGTH': sum(len(b.instructions) for b in self.function.blocks)}[op]
            code = dest(str(number))
            if op=='GET_SCRIPT_HASH' and self.scratch_base is not None:
                context=self.function.debug_metadata['security_context_upvalue']
                code=dest('_BU['+str(context+1)+'][1]['+str(self.program.security.slots['script_hash'])+']()')
            if fields['results'].count is None: code += '_BT=' + str(fields['destination'].value) + '\n'
        elif op in ('VM_ABORT', 'VM_PANIC'):
            code = ('_BP=true\n' if op == 'VM_PANIC' else '') + self.api('error') + '(nil,0)\n'
        elif op == 'VM_ASSERT':
            code = 'if not (' + v('condition') + ') then ' + self.api('error') + '(nil,0) end\n'
            span = fields['results']
            if span.count: code += self.span(span) + '=' + ','.join('nil' for _ in range(span.count)) + '\n'
            elif span.count is None: code += '_BT=' + str(span.value - 1) + '\n'
        else: raise ValueError('Bare has no emitter for semantic operation ' + op)
        # Native Lua temporaries disappear when their source instruction has
        # consumed them. Retaining them in virtual registers changes weak-table
        # and suspended-coroutine observations. Captured cells remain live until
        # the shared analysis sees their close edge.
        if op in ('EQUAL', 'LESS_THAN', 'LESS_EQUAL', 'TEST', 'TEST_SET', 'FOR_LOOP', 'ITER_LOOP'):
            condition_name = '_Bcondition'
            self.outer_locals.add(condition_name)
            code += condition_name + '=' + self.conditions[block.id] + '\n'
            self.conditions[block.id] = condition_name
        if op not in ('RETURN', 'TAIL_CALL'):
            code += self.clear(self.dead_indices(ins),self.liveness.after[ins.id])
        if self.program.poisoned:
            code = 'if _BP then ' + self.api('error') + '(nil,0) end\n' + code
        return code

def emit(lowered, context):
    started = time.perf_counter()
    program = Program(lowered, context)
    source = program.source()
    lowered.backend_data['optimization'] = dict(program.optimization)
    lowered.backend_data['bare_frame_plans'] = program.frame_plans
    lowered.backend_data['bare_flow_plans'] = program.flow_plans
    context.profile.append({'phase':'bare_optimization','elapsed':0.0,**program.optimization,
                            'frames':program.frame_plans})
    from ..native_capture import bind_native_calls
    forced=['string.match','string.find','string.sub','tonumber',
        'string.byte','pcall','type','debug.getinfo','debug.gethook','debug.getmetatable']
    if set(context.output_passes)&{'string_obf','string_flow_obf','string_encode','meme_strings'}:
        forced+=['string.char','string.rep','table.concat']
    source,captured=bind_native_calls(source,forced=forced)
    context.profile.append({'phase': 'bare_codegen', 'elapsed': round(time.perf_counter() - started, 6),
                            'functions': len(program.functions), 'source_bytes': len(source.encode()),
                            'instruction_blob': False, 'opcode_dispatcher': False,
                            'block_dispatcher': True,'captured_apis':len(captured),
                            'shared_protection_primitives':True})
    if context.output_transform is not None:
        from ...passes.literal_mosaic import ACTIVE,boundary,use_mosaic
        from ...passes.function_costs import POLICY
        parent=ACTIVE.get()
        options=dict(parent.options) if parent else {}
        options.setdefault('output_cost',{'hot_operations':1,'cold_operations':3})
        service=boundary(context.output_passes,lua_version=program.version,options=options)
        token=POLICY.set(context.target.function_cost_policy())
        try:
            with use_mosaic(service):
                source, details = context.output_transform(source, list(context.output_passes))
        finally:
            POLICY.reset(token)
        context.profile.extend(details)
    from ..environment import bind_environment
    source,environment=bind_environment(source,lua_version=program.version,
        policy=context.options.get('environment_policy','compatible'),compact='minify' in context.output_passes,
        output_passes=context.output_passes,
        qualify_globals=getattr(context.target,'isolate_runtime_globals',False),ready_marker='--[[BARE_ENV_READY]]')
    from ..line_state import apply_line_state
    from ..runtime_identity import checksum
    started=time.perf_counter()
    anchor='--[[BARE_ENV_READY]]'
    from ..runtime_finalization import output_finalizer
    finalizer=output_finalizer(context.output_passes,lua_version=program.version)
    source,program.security.line_state,lines=apply_line_state(source,context.output_prefix,
        finalizer=finalizer,output_passes=list(context.output_passes),insertion_anchor=anchor,
        native_u32=program.version=='5.1',environment_source=environment,
        qualify_globals=getattr(context.target,'isolate_runtime_globals',False))
    source=source.replace(anchor,'')
    context.profile.append({'phase':'source_line_state','elapsed':round(time.perf_counter()-started,6),
                            'probe_lines':lines,'probe_count':len(lines)})
    started=time.perf_counter()
    dump=context.target.dump_function(source,context.output_prefix,context.toolchain)
    program.security.script_hash=checksum(dump)^program.security.line_state
    context.profile.append({'phase':'dump_vm_function','elapsed':round(time.perf_counter()-started,6)})
    context.profile.append({'phase':'source_protection','elapsed':0.0,
        'protected_strings':sum(isinstance(v,(str,bytes)) for v in program.security.constants),
        'protected_numbers':sum(isinstance(v,(int,float)) for v in program.security.constants)-1,
        'runtime_checks':True,'environment_policy':context.options.get('environment_policy','compatible'),
        'checks_in_semantic_ir':True})
    context.profile.append({'phase':'runtime_validation_ir','elapsed':0.0,
                            'function':program.security.validation_id,'verdict_in_ir':True,
                            'source_bytes_before_output_passes':program.validation_bytes})
    context.profile.append({'phase':'program_integrity','elapsed':0.0,
        'domains':['factory_identity','factory_metatable'],'functions':len(program.functions),
        'retired_bootstrap_factories':len(program.retired_factory_slots),
        'monitored_factories':len(program.functions)-len(program.retired_factory_slots),
        'initial':True,'factory_identity_period_guard_events':127,
        'factory_metatable_on_full_guard':True,'instruction_blob':False})
    payload=program.security.payload(literal)
    from ...names import NameAllocator
    name=NameAllocator.for_source(source).allocate('entry')
    body=source[len('return'):].lstrip()
    env=('setfenv('+name+',getfenv(1));' if program.version=='5.1' else '')
    forward=any(i.operation in ('VARARG','PACK_VARARG') for b in lowered.semantic_ir.root.blocks for i in b.instructions)
    return 'local '+name+'='+body+';'+env+'return '+name+'('+name+','+payload+(',...' if forward else '')+')'
