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

def count_files(path):
    file_count = 0
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            file_count += 1
    return file_count

def save_results(path: str, data: dict):
    with open(path, 'w') as f:
        for rule in data:
            f.write(f"{rule}: {data[rule]}\n")

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

def merge_dicts(dict1: dict, dict2: dict)-> dict:
    """ Merges two dictionaries which are in format:
    sha256: set of items
    """
    result = {}
    for key in set(dict1.keys()).union(set(dict2.keys())):
        result[key] = dict1.get(key, set()).union(dict2.get(key, set()))

    return result

def filter_keys(dict1: dict, exclude: list)-> dict:
    return {key: dict1[key] for key in dict1 if key not in exclude}

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
    yara_unpacked_result = {}
    cryfind_unpacked_result = {}
    unpacked_path = ''
    unpacked_samples = []
    exclude_list = []
    results_path = ''
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Dataset analysis pipeline")
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument('--tool', choices=['yara', 'cryfind', 'all'], default='all', help='Analysis tool to be used (default: all)')
    parser.add_argument('-p', '--packing', help='Run unpacking', default=True)
    parser.add_argument('-e', dest='exclude', action='store_true', help='Exclude files, where packing or encryption were detected, from analysis.', default=False)
    parser.add_argument('--log', dest='logging', action='store_true', default=False, help='Enable logging')
    parser.add_argument('-s', dest='save', type=str, help='Save analysis results to file')
    args = parser.parse_args()


    configure_logger(args.logging)

    if args.save:
        results_path = args.save

    # Analyze or/and unpack
    entropy_result = packing_analyzer.analyze_entropy(args.path)
    packed_samples = packing_analyzer.analyze_packers(args.path)
    obfuscated = entropy_result.union(set(packed_samples.keys()))
    if args.packing:
        unpacked_path, unpacked_samples = packing_analyzer.unpack(args.path, packed_samples)

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
            #if not args.exclude:
            yara_unpacked_result = yara_analyzer.run(unpacked_path)
            #    exclude_list = unpacked_samples
            #else:
            #    exclude_list = list(obfuscated)
            
            yara_result = yara_analyzer.run(args.path)    
        # Results for all samples: all + unpacked    
        yara1 = merge_dicts(filter_keys(yara_result, unpacked_samples), yara_unpacked_result)
        # Results for non-obfuscated samples
        yara2 = filter_keys(yara_result, list(obfuscated))
        # Results for all but packed samples
        yara3 = filter_keys(yara_result, packed_samples.keys())

        # Run cryfind
        unpacked_result = {}
        with timer():
            #if not args.exclude:
            cryfind_unpacked_result = cryfind_analyzer.run(unpacked_path)
            #    exclude_list = unpacked_samples
            #else:
            #    exclude_list = list(obfuscated)
            cryfind_result = cryfind_analyzer.run(args.path)
        
        # Results for all samples: all + unpacked
        cryfind1 = merge_dicts(filter_keys(cryfind_result, unpacked_samples), cryfind_unpacked_result)
        # Results for non-obfuscated samples
        cryfind2 = filter_keys(cryfind_result, list(obfuscated))
        # Results for all but packed samples
        cryfind3 = filter_keys(cryfind_result, packed_samples.keys())
        
        #print_results(yara_result, "yara")
        #print_results(cryfind_result, "cryfind")
        
    else:
        print("Unknown option {}".format(args.tool))

    print("Total files:", count_files(args.path))
    print("Total obfuscated:", len(list(obfuscated)))
    print("Total packed:", len(packed_samples))

    # All with unpacking
    all_yara = process_results(yara1, {})
    print_results(all_yara, "All yara")

    all_cryfind = process_results(cryfind1, {})
    print_results(all_cryfind, "All cryfind")

    combined_results = process_results(yara1, cryfind1)
    print_results(combined_results, "All")

    # Without obfuscation
    unencrypted_y = process_results(yara2, {})
    print_results(unencrypted_y, "Yara, not obfuscated")


    unencrypted_c = process_results(cryfind2, {})
    print_results(unencrypted_c, "Cryfind, not obfuscated")

    unencrypted = process_results(yara2, cryfind2)
    print_results(unencrypted, "All, not obfuscated")

    # Without packers only
    without_packing_y = process_results(yara3, {})
    print_results(without_packing_y, "Yara, Without packing or detected protectors/SFXs")

    without_packing_c = process_results(cryfind3, {})
    print_results(without_packing_c, "Cryfind, Without packing or detected protectors/SFXs")

    without_packing = process_results(yara3, cryfind3)
    print_results(without_packing, "Without packing or detected protectors/SFXs")

    if args.save:
        save_results(results_path, combined_results)

if __name__ == "__main__":
    main()