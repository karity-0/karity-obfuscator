import sys
import argparse
from pathlib import Path

class Obfuscator:
    def __init__(self):
        self.args = None

    def start(self):
        arg_parser = argparse.ArgumentParser(description="lua obfuscator")
        arg_parser.add_argument("input", help="input lua script")
        arg_parser.add_argument("-o", "--output", help="output lua sccript")
        self.args = arg_parser.parse_args()

        input_script    = self.read_input()
        output_path     = self.get_output()
        output_script   = self.obfuscate(input_script)
        self.write_output(output_path, output_script)
        print(output_path)
        sys.exit(0)

    def read_input(self):
        try:
            with open(self.args.input, encoding="utf-8") as f:
                script = f.read()
                return script
        except FileNotFoundError:
            print(f"input script {self.args.input} not found.", file=sys.stderr)
            sys.exit(1)

    def get_output(self):
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


    def obfuscate(self, script: str) -> str:
        output = f"-- obfuscated!\n{script}"
        return output
        

if __name__ == "__main__":
    obfuscator = Obfuscator()
    obfuscator.start()