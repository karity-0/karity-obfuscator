# Boolean and table reconstruction

`BOOLEAN_OBF(true/false)` and `TABLE_OBF({...})` retain existing expression syntax
and selection modes. Both passes can also be enabled for all literals.

```json
{
  "boolean_obf_options": {"mode": "mixed"},
  "table_obf_options": {"mode": "reconstruct", "max_fields": 16, "string_keys": false}
}
```

Boolean's default `expression` mode chooses sum, difference, product, XOR, mask,
or MBA predicates with randomized comparison polarity. Each result is exactly
one boolean. `dataflow` uses two local states and multiple assignments; `mixed`
chooses between the two per occurrence. Enable nested FunctionObf when these
wrappers occur inside functions and need CFF protection. Numeric operands reuse
the existing NumberExpressionEngine/Literal Mosaic; protected spans prevent
NumberObf from expanding them again. Original source numbers remain eligible.
VM output shares the scalar generator and requires no additional full-source
parse. Existing Lua 5.3 boolean pass capability requirements remain unchanged.

Table's default `mixed` mode chooses constructor reshaping or staged reconstruction
where safe. `shuffle` uses only constructor reshaping; `reconstruct` requests
staged code whenever safety/compiler budgets allow it. Staged code creates a
real table, reuses key/value locals, fills independent keyed fields, then returns
one table. It does not introduce proxies or change public key identity.
`string_keys: true` uses the existing StringObf generator for staged string keys;
it is opt-in because its cost can dominate small tables and requires Lua 5.3.

List fields with holes or unknown values remain list fields, preserving allocation
shape and sparse-array length behavior. Dense arrays of proven non-nil literals
can use staged assignments: every index 1..n is present before the table escapes,
so the length remains n. Generated indices use Literal Mosaic and protected spans.
Numeric keyed fields retain constructor order. Known key collisions, unknown
keys, global reads, calls, varargs, metamethod-capable expressions and closures
retain their original constructor structure; eligible nested constructors can
still be transformed. Lexical bindings distinguish locals from global reads.
Reconstruction uses three locals, at most `max_fields` fields (default 16,
maximum 64), and no more than the Lua 5.1 compiler's 60 captured upvalues.
Profiles report reconstruction/shuffle counts and safety/budget fallbacks.

Source StringObf applied later also sees generated key literals. Applying it
earlier can make some values calls; these remain conservatively ordered rather
than being declared pure based on spelling. No extra general-purpose proxy,
string decoder, or name allocator system is introduced.

## Measurements

The locally generated benchmark report compares commit
`5bcef98` against this implementation, Python 3.15, Lua 5.3, seed 7201.
Build times are medians of three warm samples; execution times are medians
of three batches of 1,000 executions, excluding Lua compilation. This is a
microbenchmark of the source passes, not a preset or VM-wide speed claim.

| Input / passes | Before | Default after | Explicit dataflow/reconstruct |
|---|---:|---:|---:|
| Boolean loop | 211 B | 341 B | 551 B |
| Boolean loop + NumberObf | 1,633 B | 706 B | 658 B |
| Six-field record | 115 B | 115 B | 216 B |
| Nested records | 88 B | 88 B | 292 B |
| Dense array | 65 B | 41 B | 188 B |
| Sparse array | 65 B | 45 B | 45 B |

Boolean→Number output shrinks 56.8% in this sample through removal of duplicate
numeric expansion. Boolean alone grows because operands now have bounded
numeric protection as well as more predicate families. Explicit reconstruction
adds actual dataflow protection and is more expensive: the record loop measured
approximately 127 µs/run versus 94 µs before; nested records 3.4 µs versus 1.7 µs.
The seeded default chose constructor mode for those two samples; it can choose
staged mode on other seeds. No uniform table speed improvement is claimed.

Reproduce with `python tools/profile_boolean_table.py --baseline 5bcef98
--output local/performance/boolean-table.json`. The dedicated regression covers
predicate families/types, short circuit, numeric provenance, CFF, duplicate keys,
observable globals, sparse arrays, multireturn/varargs, nested edits, upvalue
budgets, macros and Classic/Karity/MOV execution. Ordinary table modes compile
and execute on Lua 5.1 and 5.3; string-key reconstruction follows StringObf's
existing Lua 5.3 requirement.
