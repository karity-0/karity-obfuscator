# karity obfuscator
a lua 5.3 obfuscator with a custom vm protection layer.

## features

**source-level passes**
- global localization
- string encoding / obfuscation
- number obfuscation
- boolean obfuscation
- table obfuscation
- function obfuscation (CFF + opaque predicates)
- variable renaming
- minification
- anti debug

**vm protection**
- lua 5.3 VM with custom 64bit virtual instruction format
- opcode aliasing
- opcode shuffling
- opcode fusion & splitting (superopcodes)
- unused opcode pruning
- junk opcode
- opcode mutation (CFF + opaque predicates)
- junk instruction
- in-memory instruction masking
- in-memory constant pool masking
- bytecode encryption + base36 encoding
- anti tamper
- fake constant pool
- rolling opcode
- re-obfuscate vm output with passes

**packing**
- load-based packer (raw deflate + base64, pure lua stub)
- re-obfuscated packer stub with passes
--------

## requirements
```bash
pip install -r requirements.txt
```

## configuration
```bash
cp config.example.json config.json
```
```json
{
    "passes": [
        "string_obf", "boolean_obf", "number_obf", "table_obf", "function_obf",
        "vm", "anti_debug"
    ],
    "vm_output_passes": [
        "string_obf", "boolean_obf", "number_obf",
        "rename_obf", "minify"
    ],
    "vm_options": {
        "fake_handlers": true,
        "mutate_handlers": true,
        "junk_instructions": true,
        "junk_rate": 0.15
    }
}
```

## usage
```bash
# cli
python main.py input.lua
python main.py input.lua -o output.lua
python main.py input.lua -v

# gui
python obfuscator_gui.py
```

## testing
```bash
python test/run_test.py
python test/run_test.py 01 02
python test/run_test.py func
```
