"""Karity Extended Syntax: token-aware, source-preserving Lua frontend.

No generated helpers escape into the user's environment. New lazy expressions
are single-valued; ordinary Lua expressions retain their existing arity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

INTRINSICS = {
    'KARITY_GET_SCRIPT_HASH': 0, 'KARITY_GET_VM_COUNT': 0,
    'KARITY_GET_VM_ID': 0, 'KARITY_GET_LAYOUT_HASH': 0,
    'KARITY_GET_CODE_LENGTH': 0, 'KARITY_ABORT': 0,
    'KARITY_ASSERT': 1, 'KARITY_UNREACHABLE': 0, 'KARITY_PANIC': 0,
}
_CANDIDATE = re.compile(r'\?|(?:\.\.|//|[+*/%^\-])=|\bcontinue\b|\b0[bB]|\b(?:0[xX][\da-fA-F.]*|\d[\d.]*)(?:[eEpP][+-]?\d*)?_|\bKARITY_[A-Z_]+\b')
_NUMBER = re.compile(r'(?:0[xX][\da-fA-F_]*(?:\.(?!\.)[\da-fA-F_]*)?(?:[pP][+-]?[\d_]*)?|0[bB][\w]*|(?:\d[\d_]*(?:\.(?!\.)[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?[\d_]*)?)')
_NAME = re.compile(r'[A-Za-z_][A-Za-z_0-9]*')
_CODE_CANDIDATE = re.compile(
    r'--\[(?P<ceq>=*)\[.*?\](?P=ceq)\]|--[^\r\n]*'
    r'|\[(?P<seq>=*)\[.*?\](?P=seq)\]'
    r"""|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'"""
    + r'|(?P<name>' + _NAME.pattern + r')|(?P<number>' + _NUMBER.pattern
    + r')|(?P<feature>\?|(?:\.\.|//|[+*/%^\-])=)', re.DOTALL,
)
_LONG_OPEN = re.compile(r'\[(=*)\[')
_NEWLINE = re.compile(r'[\r\n]')
_LINE_BREAK = re.compile(r'\r\n|\n\r|[\r\n]')
_OPS = ('..=', '//=', '??=', '...', '::', '<<', '>>', '==', '~=', '<=', '>=', '//', '..', '+=', '-=', '*=', '/=', '%=', '^=', '??', '?.')
_KEYWORDS = frozenset('and break do else elseif end false for function goto if in local nil not or repeat return then true until while'.split())
_COMPOUND = frozenset(('+=','-=','*=','/=','%=','^=','..=','//=','??='))
_FEATURE_TOKENS = _COMPOUND | frozenset(('??','?.','?','continue',*INTRINSICS))


class KESError(ValueError):
    def __init__(self, source: str, offset: int, message: str):
        self.offset = offset
        self.line, line_start = 1, 0
        for newline in _LINE_BREAK.finditer(source, 0, offset):
            self.line += 1
            line_start = newline.end()
        self.column = offset - line_start + 1
        super().__init__(f'KES line {self.line}, column {self.column}: {message}')


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int
    kind: str = 'symbol'


def lex(source: str) -> list[Token]:
    """Lex Lua and KES; trivia remains untouched in source slices."""
    result = []
    p, n = 0, len(source)
    while p < n:
        ch = source[p]
        if ch.isspace() or ch == '\ufeff':
            p += 1
            continue
        if (p == 0 and source.startswith('#!', p)) or (ch == '@' and not source[source.rfind('\n',0,p)+1:p].strip()):
            q = source.find('\n', p)
            p = n if q < 0 else q
            continue
        comment = source.startswith('--', p)
        q = p + 2 if comment else p
        long = _LONG_OPEN.match(source,q) if source[q:q+1] == '[' else None
        if long:
            close = ']' + long[1] + ']'
            end = source.find(close, q + len(long[0]))
            if end < 0:
                raise KESError(source, p, 'unfinished long comment' if comment else 'unfinished long string')
            end += len(close)
            if not comment:
                result.append(Token(source[p:end],p,end,'string'))
            p = end
            continue
        if comment:
            newline = _NEWLINE.search(source,p)
            p = newline.start() if newline else n
            continue
        if ch in ('"', "'"):
            q = p + 1
            while q < n and source[q] != ch:
                if source[q] == '\\':
                    q += 2
                    if q < n and source[q-1:q+1] in ('\r\n','\n\r'):
                        q += 1
                else:
                    q += 1
            if q >= n:
                raise KESError(source,p,'unfinished string')
            q += 1
            result.append(Token(source[p:q],p,q,'string')); p=q
            continue
        match = _NUMBER.match(source,p)
        if match:
            q=match.end();result.append(Token(match[0],p,q,'number'));p=q;continue
        match = _NAME.match(source,p)
        if match:
            q=match.end();text=match[0]
            result.append(Token(text,p,q,'keyword' if text in _KEYWORDS else 'name'));p=q;continue
        op=next((op for op in _OPS if source.startswith(op,p)),ch)
        result.append(Token(op,p,p+len(op)));p+=len(op)
    result.append(Token('<eof>',n,n,'eof'))
    return result


@dataclass(eq=False)
class Binding:
    name: str
    replacement: str | None = None


@dataclass
class Node:
    start: int
    end: int
    kind: str = 'plain'
    children: list[Node] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    vararg: bool = False


@dataclass(frozen=True)
class SourceRange:
    generated_start: int
    generated_end: int
    original_start: int
    original_end: int


@dataclass(frozen=True)
class LoweringResult:
    source: str
    original: str
    ranges: tuple[SourceRange, ...] = ()
    intrinsic_positions: tuple[tuple[str, int], ...] = ()

    def original_offset(self, offset: int) -> int:
        if not self.ranges:
            return min(offset,len(self.original))
        for span in self.ranges:
            if span.generated_start <= offset < span.generated_end:
                return span.original_start + min(offset-span.generated_start, max(0,span.original_end-span.original_start-1))
        return len(self.original)


class Parser:
    # Binding powers follow Lua 5.3. Ternary is weakest; coalescing follows it.
    binary = {'or':(3,4),'and':(4,5),'??':(2,2),'<':(5,6),'>':(5,6),'==':(5,6),'~=':(5,6),'<=':(5,6),'>=':(5,6),
              '|':(6,7),'~':(7,8),'&':(8,9),'<<':(9,10),'>>':(9,10),'..':(10,10),
              '+':(11,12),'-':(11,12),'*':(12,13),'/':(12,13),'//':(12,13),'%':(12,13),'^':(14,14)}

    def __init__(self, source: str, version: str):
        self.source, self.version = source, version
        self.tokens = lex(source); self.i = 0
        if version == '5.1':
            self.tokens = [Token(t.text, t.start, t.end, 'name') if t.text == 'goto' else t
                           for t in self.tokens]
        self.names = {t.text for t in self.tokens if t.kind == 'name'}
        self.counter = 0
        self.scopes: list[dict[str,Binding]] = [{}]
        self.loops: list[dict] = []
        self.calls: list[tuple[str,int]] = []
        self.intrinsic_nodes: list[Node] = []

    @property
    def token(self): return self.tokens[self.i]

    def take(self, text=None):
        t=self.token
        if t.kind=='eof':
            self.error(t, 'unexpected end of input' if text is None else f'expected {text!r}, got end of input')
        if text is not None and t.text!=text:
            self.error(t, f'expected {text!r}, got {t.text!r}')
        self.i+=1
        return t

    def accept(self,text):
        if self.token.text==text: return self.take()
        return None

    def error(self,t,message): raise KESError(self.source,t.start,message)

    def fresh(self):
        while True:
            self.counter+=1
            name=f'__kes_{self.counter}'
            if name not in self.names:
                self.names.add(name);return name

    def name(self, *, declaration=False, field_name=False):
        t=self.take()
        if t.kind!='name': self.error(t,'expected identifier')
        if t.text in INTRINSICS and (declaration or field_name):
            self.error(t,'reserved intrinsic name cannot be bound or used as a field')
        binding=None
        if declaration:
            binding=Binding(t.text);self.scopes[-1][t.text]=binding
        elif not field_name:
            binding=next((s[t.text] for s in reversed(self.scopes) if t.text in s),None)
        node=Node(t.start,t.end,'name',data={'text':t.text,'binding':binding})
        if binding is None and not field_name and not declaration and self.version=='5.3':
            node.data['environment']=next((s['_ENV'] for s in reversed(self.scopes) if '_ENV' in s),None)
        if t.text in INTRINSICS: self.intrinsic_nodes.append(node)
        return node

    def make(self,start,kind,children=(),**data):
        children=list(children)
        return Node(start,self.tokens[self.i-1].end,kind,children,data,any(c.vararg for c in children))

    def later_colon(self):
        depth=0; ternaries=0
        for token in self.tokens[self.i+1:]:
            text=token.text
            if depth==0 and text in (',',';',')',']','}','end','then','else','elseif','do','until','<eof>'):return False
            if text in ('(','[','{'):depth+=1
            elif text in (')',']','}'):depth-=1
            elif depth==0:
                if text=='?':ternaries+=1
                elif text==':':
                    if ternaries:ternaries-=1
                    else:return True
        return False

    def expression(self, minimum=0, stop_colon=False):
        t=self.token
        if t.text in ('-','not','#','~'):
            self.take();left=self.make(t.start,'plain',[self.expression(13,stop_colon)])
        elif t.text=='function':
            self.take();left=self.function(t.start)
        elif t.text=='{': left=self.table()
        elif t.text=='(':
            self.take();e=self.expression();self.take(')');left=self.make(t.start,'paren',[e])
        elif t.kind=='name': left=self.name()
        elif t.kind in ('number','string') or t.text in ('nil','false','true','...'):
            self.take();left=self.make(t.start,'number' if t.kind=='number' else 'plain')
            left.vararg=t.text=='...'
        else: self.error(t,'expected expression')
        while True:
            op=self.token.text
            if op in ('.','?.'):
                self.take();key=self.name(field_name=True)
                left=self.make(left.start,'optional' if op=='?.' else 'field',[left,key]);continue
            if op=='[':
                self.take();key=self.expression();self.take(']')
                left=self.make(left.start,'index',[left,key]);continue
            if op==':' and self.tokens[self.i+1].kind=='name' and (self.tokens[self.i+2].text in ('(','{') or self.tokens[self.i+2].kind=='string'):
                spaced=(self.source[self.token.start-1:self.token.start].isspace() or self.source[self.token.end:self.token.end+1].isspace())
                if stop_colon and (spaced or not self.later_colon()):break
                self.take();method=self.name(field_name=True);args=self.arguments()
                left=self.make(left.start,'method',[left,method,*args]);continue
            if op in ('(','{') or self.token.kind=='string':
                args=self.arguments();callee=left
                left=self.make(left.start,'call',[callee,*args])
                if callee.kind=='name' and callee.data['text'] in INTRINSICS:
                    name=callee.data['text']
                    if len(args)!=INTRINSICS[name]: self.error(self.tokens_at(callee.start),f'{name} expects {INTRINSICS[name]} arguments')
                    if any(a.vararg or a.kind=='call' for a in args[-1:]):
                        # Assert consumes one adjusted value, including f() / (...).
                        if name!='KARITY_ASSERT': self.error(self.tokens_at(callee.start),'invalid intrinsic arguments')
                    callee.data['direct']=True;self.calls.append((name,callee.start))
                    if name=='KARITY_ASSERT': left.kind='intrinsic_assert'
                continue
            if op=='?' and minimum<=1:
                self.take();yes=self.expression(stop_colon=True);self.take(':');no=self.expression(1,stop_colon)
                left=self.make(left.start,'ternary',[left,yes,no]);continue
            power=self.binary.get(op)
            if power is None or power[0]<minimum: break
            self.take();right=self.expression(power[1],stop_colon)
            left=self.make(left.start,'coalesce' if op=='??' else 'plain',[left,right])
        return left

    def tokens_at(self,start): return next(t for t in self.tokens if t.start==start)

    def arguments(self):
        if self.accept('('):
            args=[] if self.token.text==')' else self.exprlist()
            self.take(')');return args
        if self.token.text=='{': return [self.table()]
        if self.token.kind=='string':
            t=self.take();return [Node(t.start,t.end)]
        self.error(self.token,'expected call arguments')

    def exprlist(self):
        result=[self.expression()]
        while self.accept(','): result.append(self.expression())
        return result

    def table(self):
        start=self.take('{').start;children=[]
        while self.token.text!='}':
            if self.accept('['):
                children.append(self.expression());self.take(']');self.take('=');children.append(self.expression())
            elif self.token.kind=='name' and self.tokens[self.i+1].text=='=':
                children.append(self.name(field_name=True));self.take('=');children.append(self.expression())
            else: children.append(self.expression())
            if not (self.accept(',') or self.accept(';')): break
        self.take('}');return self.make(start,'plain',children)

    def function(self,start,method=False):
        self.take('(');self.scopes.append({});oldloops=self.loops;self.loops=[];params=[]
        if method:self.scopes[-1]['self']=Binding('self')
        if self.token.text!=')':
            while True:
                if self.accept('...'):break
                params.append(self.name(declaration=True))
                if not self.accept(','):break
        self.take(')');body=self.block({'end'},scope=False);self.take('end')
        self.scopes.pop();self.loops=oldloops
        node=self.make(start,'plain',[*params,body]);node.vararg=False
        return node

    def block(self,stops,*,scope=True):
        start=self.tokens[self.i-1].end if self.i else 0
        if scope:self.scopes.append({})
        children=[]
        while self.token.text not in stops and self.token.kind!='eof':
            children.append(self.statement())
        end=self.token.start
        bindings=list(self.scopes[-1].values())
        if scope:self.scopes.pop()
        return Node(start,end,'plain',children,{'bindings':bindings})

    def statement(self):
        t=self.token;word=t.text
        if word==';': self.take();return self.make(t.start,'plain')
        if word=='if':
            self.take();children=[]
            while True:
                children.append(self.expression());self.take('then');children.append(self.block({'elseif','else','end'}))
                if not self.accept('elseif'):break
            if self.accept('else'):children.append(self.block({'end'}))
            self.take('end');return self.make(t.start,'plain',children)
        if word=='do':
            self.take();body=self.block({'end'});self.take('end');return self.make(t.start,'plain',[body])
        if word in ('while','repeat','for'):return self.loop()
        if word=='local':
            self.take()
            if self.accept('function'):
                name=self.name(declaration=True);fn=self.function(self.token.start)
                return self.make(t.start,'local_function',[name,fn],bindings=[name.data['binding']])
            names=[]
            while True:
                nt=self.take()
                if nt.kind!='name':self.error(nt,'expected local name')
                if nt.text in INTRINSICS:self.error(nt,'reserved intrinsic name cannot be bound')
                names.append(nt)
                if not self.accept(','):break
            values=self.exprlist() if self.accept('=') else []
            nodes=[]
            for nt in names:
                binding=Binding(nt.text);self.scopes[-1][nt.text]=binding
                nodes.append(Node(nt.start,nt.end,'name',data={'text':nt.text,'binding':binding}))
            return self.make(t.start,'local',[*nodes,*values],names=nodes,values=values,bindings=[n.data['binding'] for n in nodes])
        if word=='function':
            self.take();name=self.name();parts=[name];method=False
            while self.accept('.'):parts.append(self.name(field_name=True))
            if self.accept(':'):parts.append(self.name(field_name=True));method=True
            fn=self.function(self.token.start,method);return self.make(t.start,'plain',[*parts,fn])
        if word=='return':
            self.take();values=[]
            if self.token.text not in ('end','else','elseif','until',';','<eof>'):values=self.exprlist()
            return self.make(t.start,'plain',values)
        if word=='break' or (word=='continue' and self.tokens[self.i+1].kind!='string'
                             and self.tokens[self.i+1].text not in ('=',',','(','{','.','?.','[',':',*_COMPOUND)):
            self.take()
            if not self.loops:self.error(t,f'{word} outside a loop')
            loop=self.loops[-1]
            if word=='continue':loop['continue']=True
            return self.make(t.start,word,loop=loop)
        if word=='goto' and self.version!='5.1':
            self.take();self.name(field_name=True);return self.make(t.start,'plain')
        if word=='::':
            self.take();self.name(field_name=True);self.take('::');return self.make(t.start,'plain')
        left=self.expression()
        if self.token.text in _COMPOUND:
            op=self.take()
            if left.kind not in ('name','field','index'):self.error(op,'compound assignment requires a variable or table field')
            if op.text=='//=' and self.version=='5.1':self.error(op,'//= requires Lua 5.3')
            right=self.expression();return self.make(t.start,'compound',[left,right],operator=op.text[:-1])
        if self.token.text in ('=',','):
            lefts=[left]
            while self.accept(','):lefts.append(self.expression())
            self.take('=');rights=self.exprlist()
            if any(x.kind not in ('name','field','index') for x in lefts):self.error(t,'invalid assignment target')
            return self.make(t.start,'plain',[*lefts,*rights])
        if left.kind not in ('call','method','intrinsic_assert'):self.error(t,'expected assignment or function call')
        return left

    def loop(self):
        t=self.take();kind=t.text;children=[];self.scopes.append({})
        loop={'continue':False,'flag':None,'kind':kind}
        if kind=='while':
            children.append(self.expression());self.take('do')
        elif kind=='for':
            names=[self.take()]
            while self.accept(','):names.append(self.take())
            numeric=bool(self.accept('='))
            if not numeric:self.take('in')
            children.extend(self.exprlist());self.take('do')
            for nt in names:
                if nt.kind!='name' or nt.text in INTRINSICS:self.error(nt,'invalid loop variable')
                self.scopes[-1][nt.text]=Binding(nt.text)
        self.loops.append(loop)
        body=self.block({'until'} if kind=='repeat' else {'end'})
        # Repeat's until expression shares the body's lexical scope.
        if kind=='repeat':
            self.scopes.append({b.name:b for b in body.data['bindings']})
            self.take('until');condition=self.expression();self.scopes.pop();children.append(condition)
        else:self.take('end')
        self.loops.pop();self.scopes.pop()
        if loop['continue']:
            loop['flag']=self.fresh()
            if kind=='repeat':
                for child in body.children:
                    for binding in child.data.get('bindings',[]):binding.replacement=self.fresh()
        return self.make(t.start,'loop',[*children,body],body=body,loop=loop)

    def parse(self):
        root=self.block({'<eof>'},scope=False)
        for node in self.intrinsic_nodes:
            if not node.data.get('direct'):
                raise KESError(self.source,node.start,'intrinsics permit direct calls only; binding, aliasing and assignment are forbidden')
        return root

    def splice(self,node,edits):
        out=[];p=node.start
        for start,end,text in sorted(edits):
            if start<p:raise RuntimeError('overlapping KES source edits')
            out.extend((self.source[p:start],text));p=end
        out.append(self.source[p:node.end]);return ''.join(out)

    def render(self,node):
        k=node.kind;c=node.children
        if k=='name':
            binding=node.data.get('binding');environment=node.data.get('environment')
            if binding and binding.replacement:return binding.replacement
            if environment and environment.replacement and node.data['text'] not in INTRINSICS:
                return environment.replacement+'.'+node.data['text']
            return node.data['text']
        if k=='number':return self.number(node)
        if k in ('continue','break'):
            loop=node.data['loop']
            if loop['continue']:return 'do '+('' if k=='continue' else loop['flag']+'=true; ')+'break end'
        if k=='compound':
            left,right=c;op=node.data['operator'];rv=self.render(right);pre=[]
            if left.kind=='name':target=self.render(left)
            else:
                table,key=left.children;a,b=self.fresh(),self.fresh()
                keytext=self.render(key) if left.kind=='index' else repr(key.data['text'])
                pre.append(f'local {a}=({self.render(table)}); local {b}=({keytext}); ');target=f'{a}[{b}]'
            old=self.fresh();pre.append(f'local {old}={target}; ')
            action=f'if {old}==nil then {target}=({rv}) end' if op=='??' else f'{target}={old} {op} ({rv})'
            return 'do '+''.join(pre)+action+' end'
        if k in ('coalesce','optional','ternary'):
            args='...';call='...' if node.vararg else '';params=args if node.vararg else ''
            if k=='ternary':
                cond,yes,no=map(self.render,c)
                body=f'if {cond} then return ({yes}) else return ({no}) end'
            else:
                temp=self.fresh();params=temp+(',...' if node.vararg else '')
                call=f'({self.render(c[0])})'+(',...' if node.vararg else '')
                other=self.render(c[1])
                if k=='optional':body=f'if {temp}==nil then return nil else return ({temp}.{other}) end'
                else:body=f'if {temp}~=nil then return {temp} else return ({other}) end'
            return f'((function({params}) {body} end)({call}))'
        if k=='intrinsic_assert':
            # Force a single argument even for f() or a vararg expression.
            return self.render(c[0])+'(('+self.render(c[1])+'))'
        if k=='loop' and node.data['loop']['continue']:
            body=node.data['body'];loop=node.data['loop'];hoisted=[];edits=[]
            for child in body.children:
                if loop['kind']=='repeat' and child.kind in ('local','local_function'):
                    hoisted.extend(b.replacement for b in child.data['bindings'])
                    if child.kind=='local':
                        names=','.join(self.render(n) for n in child.data['names'])
                        values=','.join(self.render(n) for n in child.data['values']) or 'nil'
                        text=names+'='+values
                    else:
                        text=self.render(child.children[0])+'=function'+self.render(child.children[1])
                    edits.append((child.start,child.end,text))
                else:edits.append((child.start,child.end,self.render(child)))
            inner=self.splice(body,edits)
            prefix=' local '+loop['flag']+'=false; '+('local '+','.join(hoisted)+'; ' if hoisted else '')+'repeat '
            suffix=' until true; if '+loop['flag']+' then break end; '
            rendered=prefix+inner+suffix
            return self.splice(node,[(x.start,x.end,rendered if x is body else self.render(x)) for x in c])
        return self.splice(node,[(x.start,x.end,self.render(x)) for x in c])

    def number(self,node):
        text=self.source[node.start:node.end]
        if '_' not in text and not text.lower().startswith('0b'):return text
        if text.lower().startswith('0b'):
            digits=text[2:]
            if not re.fullmatch(r'[01]+(?:_[01]+)*',digits):raise KESError(self.source,node.start,'invalid binary literal')
            value=int(digits.replace('_',''),2)
            if value>0xffffffffffffffff:raise KESError(self.source,node.start,'binary literal exceeds 64 bits')
            return hex(value)
        for match in re.finditer('_',text):
            alphabet='0123456789abcdefABCDEF' if text.lower().startswith('0x') and not re.search('[pP]',text[:match.start()]) else '0123456789'
            p=match.start()
            if p==0 or p+1==len(text) or text[p-1] not in alphabet or text[p+1] not in alphabet or (text.lower().startswith('0x') and p==2):
                raise KESError(self.source,node.start+p,'numeric separators must be between digits')
        return text.replace('_','')

    def emit(self,tree):
        # Linear, statement-anchored source map. A repeated large input must
        # not pay SequenceMatcher's quadratic cost just to report locations.
        parts=[];ranges=[];original_pos=0;generated_pos=0
        def append(text,start,end):
            nonlocal generated_pos
            parts.append(text)
            if text:ranges.append(SourceRange(generated_pos,generated_pos+len(text),start,end))
            generated_pos+=len(text)
        for node in tree.children:
            append(self.source[original_pos:node.start],original_pos,node.start)
            text=self.render(node);original=self.source[node.start:node.end]
            prefix=0
            for left,right in zip(original,text):
                if left!=right:break
                prefix+=1
            suffix=0
            while suffix<min(len(original),len(text))-prefix and original[-suffix-1]==text[-suffix-1]:suffix+=1
            append(text[:prefix],node.start,node.start+prefix)
            stop=len(text)-suffix
            append(text[prefix:stop],node.start+prefix,node.end-suffix)
            if suffix:append(text[stop:],node.end-suffix,node.end)
            original_pos=node.end
        append(self.source[original_pos:],original_pos,len(self.source))
        return ''.join(parts),tuple(ranges)


def lower_source(source: str, lua_version: str = '5.3') -> LoweringResult:
    if not _CANDIDATE.search(source):return LoweringResult(source,source)
    # Generated runtimes can contain megabytes of opaque literals/comments.
    # Scan those in C before allocating Python tokens for actual KES code.
    if not any(match.lastgroup == 'feature'
               or (match.lastgroup == 'name' and (match[0] == 'continue' or match[0] in INTRINSICS))
               or (match.lastgroup == 'number' and ('_' in match[0] or match[0].lower().startswith('0b')))
               for match in _CODE_CANDIDATE.finditer(source)):
        return LoweringResult(source,source)
    parser=Parser(source,lua_version)
    # A candidate in a string/comment alone must not reparse ordinary source.
    if not any(t.text in _FEATURE_TOKENS or (t.kind=='number' and ('_' in t.text or t.text.lower().startswith('0b'))) for t in parser.tokens):
        return LoweringResult(source,source)
    tree=parser.parse();result,ranges=parser.emit(tree)
    if result==source:return LoweringResult(source,source,(),tuple(parser.calls))
    return LoweringResult(result,source,ranges,tuple(parser.calls))


def reject_native_intrinsics(source: str) -> None:
    if 'KARITY_' not in source:return
    for token in lex(source):
        if token.kind=='name' and token.text in INTRINSICS:
            raise KESError(source,token.start,f'{token.text} requires an actual VM execution region')
