# karity obfuscator
a lua 5.3 obfuscator with a custom vm protection layer.
![beforeAfter](images/1.png)

## quick start
```bash
pip install -r requirements.txt
cp config.example.json config.json
python main.py hello.lua
```

## features
**source protection**
- type-specific obfuscation
- control flow flattening and opaque predicates
- identifier obfuscation
- anti-debug and anti-decompile

**VM protection**
- custom Lua 5.3 virtual machine
- opcode virtualization and randomization
- handler mutation
- multi-VM support

**encryption & integrity**
- bytecode and constant encryption
- anti-tamper and anti-dump
- runtime protection
- code packer

For a complete list of passes and configuration options, see
[`docs/configuration.md`](docs/configuration.md).

--------

## preview
![after1](images/2.png)
![after2](images/3.png)
![gui](images/4.png)

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