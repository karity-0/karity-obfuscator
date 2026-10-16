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

## Remaining GC limitation

These checks do not promise identical GC timing while a VM frame remains
active. Dead temporary register values and Karity's frame value vault can
retain objects until that frame exits. One observed example is creating and
resuming a coroutine, setting the local coroutine variable to nil, and running
GC in the same active VM frame: its suspended locals can remain alive longer
than under native Lua. The escaped-upvalue/error-frame leak fixed here is
separate from liveness-based cleanup of active-frame temporaries.

Native reference: Lua's [5.3 VM](https://www.lua.org/source/5.3/lvm.c.html) and
[5.1 VM](https://www.lua.org/source/5.1/lvm.c.html).
