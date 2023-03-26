import argparse
import os
from crylib import find_const, find_api, pe_import, stackstrings
from crylib.constants.CryptoConstants import constants as cryptoConstants
from crylib.constants.CryptoAPI import apis as cryptoAPIs

def analyze_file(file):
    constants, apis = cryptoConstants, cryptoAPIs
    methods = 'constant,stackstrings,api,peimport'.split(',')
    with open(file, 'rb') as f:
            binary = f.read()

    # Searching for constants
    results = find_const(binary, constants)
    for result in results:
        print(result)
    
    # Searching for API
    results = find_api(binary, apis)
    for result in results:
        print(f'[+] DLL - {result["name"]}')
        #if not summary:
        for function in result['functions']:
            print(f'    | {function["name"]}: {", ".join([hex(address) for address in function["addresses"]])}')

    # Searching for API in PE Import Tables
    try:
        results = pe_import(binary)
        for result in results:
            print(f'[+] {result["dll"]}: {result["function"]}')
        if not results:
            print('[-] Nothing Found')
    except (ImportError, ValueError) as e:
        print(f'[-] {e}')


def run(filepath):
    stats = {}

    if isinstance(filepath, list):
        # Analyze each file using the YARA rules
        for filepath in filepath:
            analyze_file(filepath)
    elif os.path.isdir(filepath):
            # Handle the folder here.
            print(f"Handling folder: {filepath}")
            for file_name in os.listdir(filepath):
                file_path = os.path.join(filepath, file_name)
                if os.path.isfile(file_path):
                    # Handle the file here.
                    analyze_file(file_path)
                else:
                    pass
                    #print(f"  - Skipping non-file: {file_path}")
    elif os.path.isfile(filepath):
        # Handle the file here.
        print(f"Handling file: {filepath}")
        analyze_file(filepath)
    else:
        print(f"Error: {filepath} is not a valid path.")


    for rule in stats:
        print(f"{rule}: {stats[rule]}")


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="YARA analyzer")
    parser.add_argument("path", help="File, directory or list of files to analyze")
    args = parser.parse_args()

    run(args.path)


if __name__ == "__main__":
    main()