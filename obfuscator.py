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
            input_name  = input_path.stem
            input_ext   = input_path.suffix
            return f"{input_name}_obfuscated{input_ext}"
        return self.args.output

    def obfuscate(self, script: str) -> str:
        output = f"-- obfuscated!\n{script}"
        return output
        

if __name__ == "__main__":
    obfuscator = Obfuscator()
    obfuscator.start()