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

*opcode & architecture*
- lua 5.3 VM with custom 64-bit virtual instruction format
- opcode aliasing / shuffling / rolling
- opcode fusion & splitting (superopcodes)
- unused opcode pruning
- handler mutation (control flow flattening + opaque predicates + junk)

*encryption*
- bytecode encryption + base36 encoding (at rest)
- in-memory bytecode encryption (runtime)
- constant pool encryption (in-memory)
- fake constant pool (decoys)

*integrity*
- anti-tamper (self-crc keyed) — also anti-dump via in-memory-only decryption
- re-obfuscate vm output with passes

**packing**
- load-based packer (raw deflate + base64)
- re-obfuscate packer stub with passes
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
