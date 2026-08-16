<!-- TODO(karity):
generate this document automatically from PASS_REGISTRY. (registry.py)
-->

# configuration

## table of contents
- feature passes
  - [remove_comment](#remove_comment)
  - [string_encode](#string_encode)
  - [string_obf](#string_obf)
  - [boolean_obf](#boolean_obf)
  - [number_obf](#number_obf)
  - [table_obf](#table_obf)
  - [function_obf](#function_obf)
  - [rename_obf](#rename_obf)
  - [localize_globals](#localize_globals)
  - [minify](#minify)
  - [vm](#vm)
  - [anti_debug](#anti_debug)
  - [anti_decompile](#anti_decompile)
  - [pack](#pack)
- [vm_options](#vm_options)
   - [dispatcher_type](#dispatcher_type)
   - [blob_form](#blob_form)
   - [vm_count](#vm_count)
   - [fake_handlers](#fake_handlers)
   - [mutate_handlers](#mutate_handlers)
   - [junk_instructions](#junk_instructions)
   - [junk_rate](#junk_rate)



## remove_comment
**group:** pre pass  
**type:** passes | vm_output_passes | packer_output_passes  

removes comments from the source code.


## string_encode
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

encodes string literals.


## string_obf
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

obfuscates string literals.


## boolean_obf
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

obfuscates boolean literals.


## number_obf
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

obfuscates number literals.


## table_obf
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

obfuscates table variables.


## function_obf
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

obfuscates functions using control flow flattening and other techniques.


## rename_obf
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

renames variable identifiers.


## localize_globals
**group:** base pass  
**type:** passes | vm_output_passes | packer_output_passes  

converts global variable accesses to local references where possible.


## minify
**group:** post pass  
**type:** passes | vm_output_passes | packer_output_passes  

reduces script size by removing unnecessary whitespace.


## vm
**group:** post pass  
**type:** passes

virtualizes Lua bytecode using a custom virtual machine.

Integer ADD handlers are generated as build-specific function DAGs with randomized
topological layouts and equivalent mixed boolean-arithmetic expressions. The VM also
performs bytecode control-flow liveness analysis and may diffuse intermediate state
through registers proven dead after an ADD. Diffusion is skipped when no safe dead
register is available.


## anti_debug
**group:** pre pass  
**type:** passes

inserts anti-debugging checks.


## anti_decompile
**group:** base pass  
**type:** passes

applies techniques to hinder decompilation while preserving program behavior.


## pack
**group:** post pass  
**type:** passes

compresses and packs the obfuscated script into a self-extracting loader.



## vm_options

### dispatcher_type

VM dispatcher shape. per obfuscation run the emitted VM uses one of these.

| Value | Description |
|--------|-------------|
| ifelseif | classic if/elseif dispatcher |
| tailcall | function table + tail-call dispatcher |
| table | alias for the function-table tail-call dispatcher |
| bsearch | nested binary-search (if/else) tree over the opcode |
| splitN | split handlers across N smaller if/elseif dispatcher functions, for example `split4` |
| bsplitN | split handlers across N smaller binary-search dispatcher functions, for example `bsplit6` |
| mixed | randomly choose per VM from `split4`, `split6`, `bsplit4`, `bsplit6`, `tailcall`, and `table` |

default: `ifelseif`

---

### blob_form

how the encrypted bytecode blob is stored in the output.

| Value | Description |
|--------|-------------|
| string | single base36 string literal |
| table | base36 blob split into chunks, stored as a key-scrambled string table (reassembled via table.concat) |
| numeric | blob stored as a key-scrambled table of 32-bit integers `{[n]=…,…}` (base36 skipped, bytes rebuilt at runtime) |
| random | randomly choose per obfuscation run |

default: `random`

---

### vm_count

number of independent VM interpreters.

higher values:
- increase diversity
- increase file size

default: 3

---

### fake_handlers

insert unreachable fake opcode handlers.

default: true

---

### mutate_handlers

apply CFF, opaque predicates and junk to all handlers.

default: true

---

### junk_instructions

insert junk virtual instructions.

default: true

---

### junk_rate

probability of inserting junk virtual instructions.

range: 0.0 ~ 1.0

default: 0.30

---
