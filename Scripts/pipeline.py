from ast import arg
import os
import glob
import argparse

samples_folder = "/home/kali/Downloads/Windows"
samples_folder = "/home/kali/Documents/Samples/malware_nocompression"
strings_out_folder = "/home/kali/Downloads/strings_result/"
yara_out_folder = "/home/kali/Documents/yara_result_unp_nc/"

strings_cmd = "strings"

def build_shell_command(command, arguments_list: list()):
    separator = " "
    args = separator.join(arguments_list)
    return command + " " + args

#command = build_shell_command(strings_cmd, ["/home/kali/Downloads/Windows/MSIL_Filecoder.CS.ex > /home/kali/Downloads/analysis.txt"])
#os.system(command)

def iterate_samples(folder, command, arguments_before, arguments_after, outputPath):
    files = glob.glob(folder + "/*")
    non_empty_yara_files = 0
    # check the output directiry
    if not os.path.exists(outputPath):
            os.mkdir(outputPath)

    for filepath in files:
        args = []
        args.extend(arguments_before)
        args.append(filepath)
        args.extend(arguments_after)
        args.append(">")
        basename = os.path.basename(filepath)
        final_filename = basename.replace(".ex", ".txt")
        args.append(os.path.join(outputPath, final_filename))
        cmd = build_shell_command(command, args)
        print("Executing: $", cmd)
        os.system(cmd)

        #check if file is empty
        if os.stat(os.path.join(outputPath, final_filename)).st_size == 0:
            os.remove(os.path.join(outputPath, final_filename))
        else:
            non_empty_yara_files += 1
            
        
    print("Non empty files:", non_empty_yara_files)
        

def checkPackers(dir, outfile):
    files = glob.glob(dir + "/*")
    
    for filepath in files:
        basename = os.path.basename(filepath)
        f = open(outfile, "a")
        f.write(basename + '\n')
        f.close()

        args = []
        args.append("-j")
        args.append(filepath)
        args.append(">>")
        args.append(outfile)
        cmd = build_shell_command("diec", args)
        os.system(cmd)


#iterate_samples(samples_folder, strings_cmd, [], [""], strings_out_folder)

yara_cmd = "yara"
yara_rules_path = "/home/kali/Downloads/crypto_signatures.yara"
yara_args = ["-s", "-r", yara_rules_path]

#iterate_samples(samples_folder, yara_cmd, yara_args, [], yara_out_folder)

out = "/home/kali/Documents/Workspace/subsetNormal-packers-info.json"
#checkPackers(samples_folder, out)

import logging
import sys
import yara_analyzer
import cryfind_analyzer
import packing_analyzer
import time
import lief
import contextlib

root = logging.getLogger()

@contextlib.contextmanager
def timer():
    start = time.time()
    yield
    end = time.time()
    print('Analysis took {} seconds'.format(end - start))

def configure_logger(enabled):
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    root.addHandler(handler)
    if not enabled:
        root.disabled = True
        # disable error log for cryfind using lief
        lief.logging.disable()

def merge_dicts(dict1, dict2):
    """ Merges two dictionaries which are in format:
    sha256: set of items
    Changes updates the first dictionary with values from
    the second. 
    """
    for key, value in dict2.items():
        if key in dict1:
            dict1[key].update(value)
        else:
            dict1[key] = value

# TODO: support more dicts
def process_results(dict1, dict2):
    """ Combines results of two tools. """
    new_dict = {}

    for key in set(dict1.keys()).union(set(dict2.keys())):
        # Calculate value as union of sets in old dictionaries
        value = dict1.get(key, set()).union(dict2.get(key, set()))
        # Add key-value pairs to new dictionary
        for item in value:
            new_dict[item] = new_dict.get(item, 0) + 1

    return new_dict

def print_results(data, tool_name):
    print('--------------------------------------------')
    print(f"Results after analysis with {tool_name}:")
    print('--------------------------------------------')
    for rule in data:
        print(f"{rule}: {data[rule]}") 
    print('--------------------------------------------')

def main():

    yara_result = {}
    cryfind_result = {}
    unpacked_path = ''
    unpacked_samples = []
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Dataset analysis pipeline")
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument('--tool', choices=['yara', 'cryfind', 'all'], default='all', help='Analysis tool to be used (default: all)')
    parser.add_argument('-p', '--packing', choices=['analyze', 'unpack'], default='unpack', help='Run packers/encryption analyzer')
    parser.add_argument('-e', help='Exclude files, where packing or encryption were detected, from analysis.', default=False)
    parser.add_argument('--log', dest='logging', action='store_true', default=False, help='Enable logging')
    args = parser.parse_args()


    configure_logger(args.logging)

    # Analyze or/and unpack
    if args.packing == 'analyze':
        packing_analyzer.analyze_packers(args.path)
    elif args.packing == 'unpack':
        entropy_result = packing_analyzer.analyze_entropy(args.path)
        result = packing_analyzer.analyze_packers(args.path)
        unpacked_path, unpacked_samples = packing_analyzer.unpack(args.path, result)
        obfuscated = entropy_result.union(set(result.keys()))

    # Analyze with yara only
    if args.tool == 'yara':
        with timer():
            yara_result = yara_analyzer.run(args.path, unpacked_samples)
            unpacked_result = yara_analyzer.run(unpacked_path) 
        merge_dicts(yara_result, unpacked_result)
        print_results(yara_result, "yara")
    # Analyze with cryfind only
    elif args.tool == 'cryfind':
        with timer():
            cryfind_result = cryfind_analyzer.run(args.path, unpacked_samples)
            unpacked_result = cryfind_analyzer.run(unpacked_path)
        merge_dicts(cryfind_result, unpacked_result)
        print_results(cryfind_result, "cryfind")

    elif args.tool == 'all':
        # Run yara
        with timer():
            yara_result = yara_analyzer.run(args.path, unpacked_samples)
            unpacked_result = yara_analyzer.run(unpacked_path) 
        merge_dicts(yara_result, unpacked_result)

        # Run cryfind
        unpacked_result = {}
        with timer():
            cryfind_result = cryfind_analyzer.run(args.path, unpacked_samples)
            unpacked_result = cryfind_analyzer.run(unpacked_path)
        merge_dicts(cryfind_result, unpacked_result)
        

        

        #print_results(yara_result, "yara")
        #print_results(cryfind_result, "cryfind")
        
    else:
        print("Unknown option {}".format(args.tool))

    combined_results = process_results(yara_result, cryfind_result)
    print_results(combined_results, "All")

    
if __name__ == "__main__":
    main()