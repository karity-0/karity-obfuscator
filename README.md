# lua-obfuscator

simple lua obfuscator

## structure

```
lua-obfuscator/
├── main.py                        # cli entrypoint
├── requirements.txt
├── obfuscator/
│   ├── pipeline.py                # pass pipeline
│   └── passes/
│       ├── base.py                # BasePass, Replacement
│       ├── string_encode.py       # StringEncodePass
│       └── number_obfuscation.py  # NumberObfuscationPass
└── test/
    ├── run_test.py
    ├── scripts/                   # test lua scripts
    └── output/                    # output scripts (gitignored)
```

## requirements
```bash
pip install -r requirements.txt
```

## usage

```bash
# to input_obfuscated.lua
python main.py input.lua

# to output.lua
python main.py input.lua -o output.lua

# print debug info
python main.py input.lua -v
```

## features
- string obfuscation
- number obfuscation

## passes

**StringEncodePass** — encode all strings to ascii escape string

```lua
-- before
print("hello world")

-- after
print("\104\101\108\108\111\32\119\111\114\108\100")
```

**NumberObfuscationPass** — obfuscate all numbers using xor

```lua
-- before
local a = 10

-- after
local a = (203292562~203292568)
```

## testing

```bash
python test/run_test.py
```