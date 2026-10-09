"""Private-field stripping: output equivalence and escape-analysis boundaries."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_rename_regression import run
from obfuscator import build_pipeline_from_config
from obfuscator.pipeline import Pipeline
from obfuscator.passes.strip_info import StripInfoPass, field_replacements
from obfuscator.passes.ts_utils import parse


def main():
    safe = [
        'local private={secret=1}; private["secret"]=private.secret+2; print(private.secret)',
        'local private={secret=1,["secret"]=2,a=4}; print(private.secret,private.a,private.missing)',
        'local private={secret=1,7}; private[2]=8; print(private.secret,private[1],private[2])',
        'local private={secret=1}; local function f() private.secret=private.secret+1 end; f(); print(private.secret)',
        'local private={secret=1}; do local private={secret=2}; print(private.secret) end; print(private.secret)',
        'local x,private=42,{secret=1}; print(x,private.secret)',
        'local private={secret=1}; function private.work() return 4 end; print(private.secret,private.work())',
        '-- comment\nlocal private={secret=1}; print("한글",private.secret) -- tail',
        'local private--[[separator]]={secret=1}; print(private.secret)',
        'local private={secret=1}; local alias=private; local second=alias; second.secret=4; print(private.secret,alias.secret)',
        'local private={secret=1}; do local alias=private; local function f() alias.secret=8 end; f() end; print(private.secret)',
        'local private={secret=1}; local alias=private; do local alias={secret=2}; print(alias.secret) end; print(alias.secret)',
        'local private={secret=1}; print(private[ [[secret]] ])',
        'local private={[ [=[\nsecret]=] ]=1}; print(private.secret)',
        'local private={["secret-key"]=1,[""]=2}; print(private[ [[secret-key]] ],private[""])',
        'local private={[ [=[\r\nsecret\r\nkey]=] ]=1}; print(private[ [[secret\nkey]] ])',
        r'local private={secret=1}; print(private["\115ecret"],private["\x73ecret"])',
        'local private=({secret=1}); local alias=((private)); print((alias).secret,((private))["secret"])',
        'local private={["sec" .. "ret"]=1}; print(private[("s" .. ("ec" .. "ret"))])',
        'local private={secret=1}; print(private[("sec" --[[hidden]] .. "ret")])',
        r'local private={["\000secret"]=1,["\255secret"]=2,["ÿsecret"]=3}; print(private["\0secret"],private["\xffsecret"],private["\195\191secret"])',
        r'local private={["secret\n\t\r\a\b\f\v\"\x5c"]=1}; print(private["secret\010\009\013\007\008\012\011\034\092"])',
        'local private={secret=1}; print(private["sec\\z \n\tret"])',
        'local private={["secret\\\nkey"]=1}; print(private[ [[secret\nkey]] ])',
    ]
    for source in safe:
        output = StripInfoPass().run(source)
        assert 'secret' not in output, output
        assert not parse(output).root.has_error, output
        assert run(source) == run(output), output

    # Every byte must map identically between decimal and hex spellings,
    # including NUL, quotes, slashes, and bytes that are not valid UTF-8.
    fields = ','.join(f'["\\{value:03d}"]={value}' for value in range(256))
    reads = ';'.join(f'print(private["\\x{value:02x}"])' for value in range(256))
    source = 'local private={' + fields + '};' + reads
    output = StripInfoPass().run(source)
    assert '\\x' not in output and '\\000' not in output, output
    assert run(source) == run(output)

    unsafe = [
        'return private',
        'exported=private',
        '_G.exported=private',
        '_ENV.exported=private',
        'print(private)',
        'for k,v in pairs(private) do print(k,v) end',
        'print(next(private))',
        'local key="secret"; print(private[key])',
        'print(rawget(private,"secret"))',
        'rawset(private,"secret",4)',
        'setmetatable(private,{})',
        'print(getmetatable(private))',
        'private={secret=4}; print(private.secret)',
        'local function f() return private end; print(f().secret)',
        'local box={private}; print(box[1].secret)',
        'function private:work() return self.secret end; print(private:work())',
        r'print(private["\u{73}ecret"])',
        'local part="sec"; print(private[part .. "ret"])',
        'local alias=(private); return alias',
        'local alias=(private); alias={secret=9}; print(alias.secret,private.secret)',
        'local alias=private; return alias',
        'local alias=private; exported=alias',
        'local alias=private; local second=alias; rawset(second,"secret",4); print(private.secret)',
        'local alias=private; alias={secret=9}; print(alias.secret,private.secret)',
        'local alias=private; private={secret=9}; print(alias.secret,private.secret)',
        'local alias=private; local key="secret"; print(alias[key])',
        'local alias=private; local function f() return alias end; print(f().secret)',
    ]
    for suffix in unsafe:
        source = 'local private={secret=1}; ' + suffix
        assert not field_replacements(parse(source)), source
        output = StripInfoPass().run(source)
        assert 'secret' in output, output
        # Printing table identities is nondeterministic across processes.
        if suffix != 'print(private)':
            assert run(source) == run(output), output

    for source in [
        'local private={[key]=1,secret=2}; print(private.secret)',
        'local private=external; print(private.secret)',
        'local private; private={secret=1}; print(private.secret)',
    ]:
        assert not field_replacements(parse(source)), source

    labels = [
        'local n=0; ::retry:: n=n+1; if n<3 then goto retry end; print(n)',
        'goto done; ::unused:: print("bad"); ::done:: print("ok")',
        'local n=0; ::retry:: do ::retry:: n=n+1; if n<2 then goto retry end end; if n<3 then goto retry end; print(n)',
        '::retry:: local function f() local n=0; ::retry:: n=n+1; if n<2 then goto retry end; return n end; print(f())',
    ]
    for source in labels:
        output = StripInfoPass().run(source)
        for symbol in ['retry', 'unused', 'done']:
            assert symbol not in output, output
        assert run(output) == run(source), output

    source = 'local private={secret=1}; print(private.secret) -- removed'
    for passes in [['strip_info'], ['strip_info', 'rename_obf', 'minify'],
                   ['strip_info', 'string_obf', 'table_obf', 'rename_obf']]:
        pipeline = build_pipeline_from_config({'passes': passes}, Pipeline)
        output = pipeline.run(source)
        assert run(output) == run(source)
        assert 'secret' not in output
    try:
        StripInfoPass().run('local =')
    except ValueError:
        pass
    else:
        raise AssertionError('invalid syntax accepted')
    print('strip_info regressions passed')


if __name__ == '__main__':
    main()
