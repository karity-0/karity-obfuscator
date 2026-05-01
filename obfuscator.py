import sys
import argparse
from pathlib import Path

from luaparser import ast, astnodes

def encode(s):
    return '"' + ''.join(f'\\{ord(c)}' for c in s) + '"'

class Obfuscator:
    def __init__(self):
        self.args = None

    def start(self):
        arg_parser = argparse.ArgumentParser(description="lua obfuscator")
        arg_parser.add_argument("input", help="input lua script")
        arg_parser.add_argument("-o", "--output", help="output lua script")
        self.args = arg_parser.parse_args()

        input_script    = self.read_input()
        output_path     = self.get_output_path()
        
        print("parsing script..")
        tree = ast.parse(input_script)

        print("obfuscating..")
        output_script   = self.obfuscate(input_script, tree)

        print("saving output..")
        self.write_output(output_path, output_script)
        sys.exit(0)

    def read_input(self):
        try:
            with open(self.args.input, encoding="utf-8") as f:
                script = f.read()
                return script
        except FileNotFoundError:
            print(f"input script {self.args.input} not found.", file=sys.stderr)
            sys.exit(1)

    def get_output_path(self):
        if self.args.output is None:
            input_path  = Path(self.args.input)
            return input_path.with_name(f"{input_path.stem}_obfuscated{input_path.suffix}")
        return self.args.output

    def write_output(self, path: str, script: str):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(script)
        except Exception as e:
            print(f"cant write output script {path}", file=sys.stderr)
            sys.exit(1)


    def obfuscate(self, script: str, tree) -> str:
        replacements = []
    
        for node in ast.walk(tree):
            if isinstance(node, astnodes.String):
                encoded = encode(node.raw)
                #print(ast.to_pretty_str(node))
                print(f"[String] {node.s} -> {encoded}")
                print(node.start_char, node.stop_char)
                print(node.first_token, node.last_token)
                replacements.append((
                    node.start_char,
                    node.stop_char,
                    encoded
                ))
        
        return self.apply(script, replacements)
        
    def apply(self, src, replacements):
        for start, end, new in sorted(replacements, reverse=True):
            src = src[:start] + new + src[end+1:]

        src = f"-- obfuscated!\n{src}"
        return src

if __name__ == "__main__":
    obfuscator = Obfuscator()
    obfuscator.start()