# Opcode boundary regression coverage

Run `python test/run_opcode_edges_regression.py` for native-versus-VM
comparisons on Lua 5.1 and 5.3, with Classic, Karity and MOV. Each target/backend
runs the same fixture with minimal options and with helper diversity, graph
execution, runtime polymorphism, and argument/upvalue/table virtualization.
The suite is included in `test/run_ci.py`.

For a larger numeric differential run, use
`python test/run_opcode_edges_regression.py --numeric-matrix`. It checks 1,728
combinations of initial value, limit and step on all six target/backend pairs.
Each loop stops after four iterations, including zero-step and infinite bounds.

The fixture covers numeric loop conversion and bounds, concatenation with nil
and metamethods, block/return/tail-call upvalue boundaries, shared mutable
captures, error identity, error unwinding and GC, coroutine suspension, open
argument/result lists containing nil, callable tables and false iterator keys.
The frontend check also requires FORPREP to read and write all three loop-state
registers, including the converted limit and step.

## Runtime invariants

- FORPREP validates and converts values before subtracting the step. Lua 5.3
  chooses the integer path from the original initial/step types, rounds the
  limit in the step's direction, and handles out-of-range limits; its fallback
  uses floats. Lua 5.1 uses native binary64 values. Conversion helpers capture
  their builtins before user code can replace globals.
- CONCAT preserves operand positions and an explicit count. Lua table length
  cannot represent a list of operands containing nil.
- Open upvalues use independent shared cells, not callbacks retaining the
  owner frame. Register reads and writes consult those cells, including MOV
  commits and copies. Karity's encoded fast paths exclude captured operands
  and destinations; pending arithmetic is materialized before capture.
- Closing a cell synchronizes the register value before detaching it, so
  RETURN still sees a value most recently changed by another closure.
- Only registers actually captured by a child get cells. Creating a closure
  does not itself require a cell at the destination register; recursive
  captures are created while binding the child's upvalues.
- Virtualized upvalue object references belong to the cell. Neither a global
  strong vault nor a weak-key table's values may keep a closure cycle alive.
  This is important on Lua 5.1, which has no ephemeron semantics.

`test/run_closure_gc_regression.py` checks unreachable recursive closures and
live closure descriptors with upvalue virtualization both disabled and enabled
on Karity. The register-cache, MOV and opcode-synthesis suites cover remapping,
encoded storage and synthesized commits around these boundaries.

## Active-frame ownership and GC limits

Live Karity slots own their value handles; weak vault indices do not retain
overwritten objects. Captured objects belong to shared cells rather than stale
register copies. Closure wrappers use tail bridges, private argument packets
are consumed after binding, and resume packets are released after use. After
copying call arguments, the VM clears completed call temporaries while keeping
open captured locals and RK constants. Lua 5.1 virtual tables own their hidden
descriptors until native exposure, avoiding weak-key descriptor cycles.

`test/run_vm_lifetime_regression.py` compares forced-GC observations with native
Lua for overwritten objects, live aliases, shared cells, coroutine disposal,
callable tables, exposed tables and unreachable cycles, on both Lua versions
and all backends. Open results beyond the 256 static register indices use a
separate tail, so they cannot overwrite RK constants; the suite checks through
1,100 values with trailing nil, false and object identity.

These checks cover the recorded boundaries, not identical automatic GC timing,
finalizer order, debug stack layout or arbitrary active-frame liveness. The VM
allocates helper structures and uses different native call frames. Other
observable lifetime differences should still be reduced against the matching
native interpreter and added to the differential corpus.

## Chunk arguments and module results

The generated chunk forwards its original varargs into the root VM function
and returns the root result list with its explicit count. Nil holes, trailing
nil and false are preserved. Tables leaving Karity are restored to native
tables before crossing the VM boundary.

The lifetime regression also loads output through an external observer and
`require`, checks a custom environment, and calls returned module functions
after GC. Lua 5.3 checks include source-only packing and VM plus packing.

Native reference: Lua's [5.3 VM](https://www.lua.org/source/5.3/lvm.c.html) and
[5.1 VM](https://www.lua.org/source/5.1/lvm.c.html).
