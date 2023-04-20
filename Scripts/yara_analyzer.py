import yara
import os
import argparse
import logging
import json

DEFAULT_RULES_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'crypto_signatures.yara')

def parse_yara_output(yara_output, file_name, rule_stats=None):

    rules_map = {}
    script_path = os.path.dirname(os.path.realpath(__file__))
    map_path = os.path.join(script_path, 'mapping.json')
    # load mapping from file
    with open(map_path, 'r') as f:
        rules_map = json.load(f)[0]

    # Parse the YARA output and map signatures to algorithms
    for match in yara_output:
        # Add rule to the statistics

        #primitives.add(rules_map.get(match.rule, "Other"))
        if match.rule in rules_map:
            rule_stats.setdefault(file_name, set()).add(rules_map.get(match.rule))
       

        #print("Matched rule:", match.rule)
        #print("Matched strings:")
        #for string in match.strings:
            #print("  - offset:", string[0])
            #print("    value:", string[1])
            #print("    identifier:", string[2])
            

def analyze_file(filepath, rules, rule_stats=None):
    matches = rules.match(filepath)
    if matches:
        logging.info("Analyzing file: %s", filepath)
        file_name = os.path.basename(filepath)
        parse_yara_output(matches, file_name, rule_stats)


def handle_directory(path, exclude, rules, stats=None):
    # Handle the folder here.
    print(f"Handling folder: {path}")
    logging.info("Handling directory: %s", path)
    for file_name in os.listdir(path):
        if file_name in exclude:
            continue
        file_path = os.path.join(path, file_name)
        if os.path.isfile(file_path):
            # Handle the file here.
            analyze_file(file_path, rules, stats)
        else:
            #pass
            logging.info(f"    Skipping non-file: {file_path}")

def run(filepath, exclude = list(), rules_path=DEFAULT_RULES_FILE):

    logging.info("Running yara analyzer.")

    stats = {}
    # Check rules file
    if not os.path.isfile(rules_path):
        print(f"Error, file {rules_path} does not exist")
        return

    # Load the YARA rules
    rules = yara.compile(filepath=rules_path)

    if isinstance(filepath, list):
        # Analyze each file using the YARA rules
        for filepath in filepath:
            if os.path.isdir(filepath):
                handle_directory(filepath, exclude, rules, stats)
            elif os.path.isfile(filepath):
                analyze_file(filepath, rules, stats)
            analyze_file(filepath, rules, stats)
    elif os.path.isdir(filepath):
            handle_directory(filepath, exclude, rules, stats)
    elif os.path.isfile(filepath):
        # Handle the file here.
        logging.info("Handling file: %s", filepath)
        analyze_file(filepath, rules, stats)
    else:
        logging.error("Error: %s is not a valid path.", filepath)

    return stats
    #for rule in stats:
    #    print(f"{rule}: {stats[rule]}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="YARA analyzer")
    parser.add_argument("path", help="File, directory or list of files to analyze")
    parser.add_argument("-r", "--rules", help="Path to YARA rules file", default=DEFAULT_RULES_FILE)
    args = parser.parse_args()

    run(args.path, args.rules)


if __name__ == "__main__":
    main()