import argparse
import os
from crylib import find_const, find_api, pe_import, stackstrings
from crylib.constants.CryptoConstants import constants as cryptoConstants
from crylib.constants.CryptoAPI import apis as cryptoAPIs
import logging

import contextlib
import io
import sys

# class DummyFile(object):
#     def write(self, x): pass

# @contextlib.contextmanager
# def nostdout():
#     save_stdout = sys.stdout
#     save_stderr = sys.stderr
#     sys.stdout = DummyFile()
#     sys.stderr = DummyFile()
#     yield
#     sys.stdout = save_stdout
#     sys.stderr = save_stderr

def analyze_file(file, stats=None, log = False):
    constants, apis = cryptoConstants, cryptoAPIs
    results = []
    
    logging.info(f"File: {file}")
    
    with open(file, 'rb') as f:
            binary = f.read()

    # Searching for constants
    #with nostdout():
    results = find_const(binary, constants) # TODO: add timeout? See 1ac6cc5e508c156e28ead649bba143d28c1263ace5c136cb4fe9a7bbbc28943c
    for result in results:
        stats[result.name] = stats.get(result.name, 0) + 1


    # Searching for API
    #with nostdout():
    results = find_api(binary, apis)
    for result in results:
        logging.info("[+] DLL API - %s", result["name"])
        stats[result["name"]] = stats.get(result["name"], 0) + 1
        #if not summary:
        #for function in result['functions']:
        #    print(f'    | {function["name"]}: {", ".join([hex(address) for address in function["addresses"]])}')

    # Searching for API in PE Import Tables
    try:
        #with nostdout():
        results = pe_import(binary)
        for result in results:
            #print(f'[+] {result["dll"]}: {result["function"]}')
            stats[result["dll"]] = stats.get(result["dll"], 0) + 1
        if not results:
            logging.info('[-] PE Import Tables - Nothing Found')
    except (ImportError, ValueError) as e:
        logging.error('[-] %s', e)


def run(filepath, log = False):

    logging.info("Starting cryfind analyzer.")

    stats = {}

    if isinstance(filepath, list):
        # Analyze each file using the YARA rules
        for filepath in filepath:
            analyze_file(filepath, stats)
    elif os.path.isdir(filepath):
            # Handle the folder here.
            print('Handling folder: %s', filepath)
            for file_name in os.listdir(filepath):
                file_path = os.path.join(filepath, file_name)
                if os.path.isfile(file_path):
                    # Handle the file here.
                    analyze_file(file_path, stats)
                else:
                    pass
                    #print(f"  - Skipping non-file: {file_path}")
    elif os.path.isfile(filepath):
        # Handle the file here.
        print("Handling file: %s", filepath)
        analyze_file(filepath, stats)
    else:
        logging.error("Error: %s is not a valid path.", filepath)


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