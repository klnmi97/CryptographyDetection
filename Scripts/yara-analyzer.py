import yara
import os
import argparse

DEFAULT_RULES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'crypto_signatures.yara')

def parse_yara_output(yara_output):
    # Parse the YARA output and print the matches
    for match in yara_output:
        print("Matched rule:", match.rule)
        print("Matched strings:")
        for string in match.strings:
            print("  - offset:", string[0])
            print("    value:", string[1])
            print("    identifier:", string[2])

def analyze_file(filepath, rules):
    matches = rules.match(filepath)
    if matches:
        print("File:", filepath)
        parse_yara_output(matches)


def run(filepath, rules_path=DEFAULT_RULES_FILE):

    # Check rules file
    if not os.path.isfile(rules_path):
        print(f"Error, file {rules_path} does not exist")
        return

    # Load the YARA rules
    rules = yara.compile(filepath=rules_path)

    if isinstance(filepath, list):
        # Analyze each file using the YARA rules
        for filepath in filepath:
            analyze_file(filepath, rules)
    elif os.path.isdir(filepath):
            # Handle the folder here.
            print(f"Handling folder: {filepath}")
            for file_name in os.listdir(filepath):
                file_path = os.path.join(filepath, file_name)
                if os.path.isfile(file_path):
                    # Handle the file here.
                    analyze_file(file_path, rules)
                else:
                    pass
                    #print(f"  - Skipping non-file: {file_path}")
    elif os.path.isfile(filepath):
        # Handle the file here.
        print(f"Handling file: {filepath}")
        analyze_file(filepath, rules)
    else:
        print(f"Error: {filepath} is not a valid path.")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="YARA analyzer")
    parser.add_argument("path", help="File, directory or list of files to analyze")
    parser.add_argument("-r", "--rules", help="Path to YARA rules file", default=DEFAULT_RULES_FILE)
    args = parser.parse_args()

    run(args.path, args.rules)


if __name__ == "__main__":
    main()