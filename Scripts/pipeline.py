#!/usr/bin/env python
""" The main pipeline script with commanline interface. 

    Usage: pipeline.py -h 
"""

import logging
import sys
import yara_analyzer
import cryfind_analyzer
import packing_analyzer
import time
import lief
import contextlib
import os
import argparse
import json

root = logging.getLogger()

@contextlib.contextmanager
def timer():
    start = time.time()
    yield
    end = time.time()
    print('Analysis took {} seconds'.format(end - start))

def list_files(directory_path):
    """ List files in the directory. """
    files_set = set()
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):
            files_set.add(file_name)
    return files_set

def count_files(path):
    """ Get number of file in the directory. """
    file_count = 0
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            file_count += 1
    return file_count

def save_results(path: str, data):
    """ Write data to the file. """
    with open(path, 'w') as f:
        f.write(data)

def read_file(path) -> list:
    """ Read file line by line into a list. """
    if os.path.isfile(path):
        with open(path, 'r') as f:
            lines = [line.strip() for line in f]
        return lines
    else:
        print(f"Error: {path} file does not exist or is not a file!")
        sys.exit(1)

def configure_logger(enabled):
    """ Enable or disable logger. Logs are
    printed to standard output. """
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
    sha256: list of items
    """
    result = {}
    for key in set(dict1.keys()).union(set(dict2.keys())):
        result[key] = dict1.get(key, set()).union(dict2.get(key, set()))

    return result

def filter_values(dict1: dict, filter: list)-> dict:
    """ Create a new dictionary which consists of keys 
    with values which contain any element from 
    the filter list. """
    return {key: value for key, value in dict1.items() if any(item in value for item in filter)}

def filter_keys(dict1: dict, exclude: list)-> dict:
    """ Create a new dictionary without the keys 
    provided in the exclude list. """
    return {key: dict1[key] for key in dict1 if key not in exclude}

def collect_keys(dict1: dict, include: list)-> dict:
    """ Create a new dictionary which consists of items with
    keys which are in the include list. """
    return {key: dict1[key] for key in dict1 if key in include}

def process_results(dict1, dict2):
    """ Combines results of two tools. """
    result = {}

    for key in set(dict1.keys()).union(set(dict2.keys())):
        # Calculate value as union of sets in old dictionaries
        value = dict1.get(key, set()).union(dict2.get(key, set()))
        # Add key-value pairs to new dictionary
        for item in value:
            result[item] = result.get(item, 0) + 1

    return result

def combined_len(dict1, dict2):
    """ Get length of the union of the provided dictionaries key sets. """
    return len(set(dict1.keys()).union(set(dict2.keys())))

def print_results(data, tool_name):
    """ Print results of the analysis. """
    print('--------------------------------------------')
    print(f"Results after analysis with {tool_name}:")
    print('--------------------------------------------')
    # for rule in data:
    #     print(f"{rule}: {data[rule]}")
    print(data) 
    print('--------------------------------------------')

def print_stats(total, obfusc, packed, non_obfusc):
    """ Print brief data stats. """
    print('--------------------------------------------')
    print("Total samples analyzed:", total)
    print("Total samples with high entropy or detected packers:", obfusc)
    print("Total samples with detected packers:", packed)
    print("Total files without obfuscation:", non_obfusc)
    print('--------------------------------------------')

def main():

    yara_raw = {}
    cryfind_raw = {}
    yara_unpacked_raw = {}
    cryfind_unpacked_raw = {}
    unpacked_path = ''
    unpacked_samples = []
    exclude_list = []
    results_path = ''
    results = {}
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Dataset analysis pipeline")
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument('--tool', choices=['yara', 'cryfind', 'all'], default='all', help='Analysis tool to be used (default: all)')
    parser.add_argument('-f', dest='filter', type=str, help='Filter out samples provided in the file')
    parser.add_argument('--log', dest='logging', action='store_true', default=False, help='Enable logging')
    parser.add_argument('-s', dest='save', type=str, help='Export analysis results')
    parser.add_argument('-c', '--cache', dest='cache', action='store_true', default=False, help='Cache raw analysis data/Load cached data')

    args = parser.parse_args()

    configure_logger(args.logging)

    if args.filter:
        exclude_list = read_file(args.filter)

    if args.save:
        results_path = args.save

    total_files = count_files(args.path)

    # Analyze packers and entropy and unpack
    entropy_result = packing_analyzer.analyze_entropy(args.path, args.cache)
    packed_samples = packing_analyzer.analyze_packers(args.path, use_caching=args.cache)
    obfuscated = entropy_result.union(set(packed_samples.keys()))
    non_obfuscated = [file for file in list_files(args.path) if file not in list(obfuscated)]
    unpacked_path, unpacked_samples = packing_analyzer.unpack(args.path, packed_samples)
    analysis_dirname = os.path.basename(args.path)

    # Group packers data by packers
    packers = {}
    for hash, packer_list in packed_samples.items():
        for packer in packer_list:
            if packer in packers.keys():
                packers[packer] += 1
            else:
                packers[packer] = 1

    packers["Total"] = total_files
    results["packers"] = packers

    # Run Yara analysis
    if args.tool == 'all' or args.tool == 'yara':

        tool_name = "yara"
        cache_file_yara = analysis_dirname + "_" + tool_name
        if args.cache:
            yara_unpacked_raw = packing_analyzer.load_from_cache(cache_file_yara + "_u")
            yara_raw = packing_analyzer.load_from_cache(cache_file_yara)
        if not yara_unpacked_raw or not yara_raw:
            # Run yara
            with timer():
                yara_unpacked_raw = yara_analyzer.run(unpacked_path)
                yara_raw = yara_analyzer.run(args.path)
            
            if args.cache:
                packing_analyzer.cache_data_to_disk(cache_file_yara + "_u", yara_unpacked_raw)
                packing_analyzer.cache_data_to_disk(cache_file_yara, yara_raw)

        # Results for all samples: all + unpacked    
        yara_complete = merge_dicts(filter_keys(yara_raw, unpacked_samples), yara_unpacked_raw)

        # All minus filtered
        if args.filter:
            yara_complete_filtered = filter_keys(yara_complete, exclude_list)

        # Results for non-obfuscated + unpacked
        yara_no_obfusc = merge_dicts(filter_keys(yara_raw, list(obfuscated)), yara_unpacked_raw)

        # Results for non-obfuscated + unpacked minus exclude list
        yara_no_obfusc_filtered = {}
        if args.filter:
            yara_no_obfusc_filtered = filter_keys(yara_no_obfusc, exclude_list)
    # Run cryfind analysis
    if args.tool == 'all' or args.tool == 'cryfind':
        tool_name = "cryfind"
        # Use caching
        cache_file_cryfind = analysis_dirname + "_" + tool_name
        if args.cache:
            cryfind_unpacked_raw = packing_analyzer.load_from_cache(cache_file_cryfind + "_u")
            cryfind_raw = packing_analyzer.load_from_cache(cache_file_cryfind)
        if not cryfind_unpacked_raw or not cryfind_raw:
            # Run measured analysis
            with timer():
                cryfind_unpacked_raw = cryfind_analyzer.run(unpacked_path)
                cryfind_raw = cryfind_analyzer.run(args.path)
            # Cache raw results
            if args.cache:
                packing_analyzer.cache_data_to_disk(cache_file_cryfind + "_u", cryfind_unpacked_raw)
                packing_analyzer.cache_data_to_disk(cache_file_cryfind, cryfind_raw)
        
        # Results for all samples: all + unpacked
        cryfind_complete = merge_dicts(filter_keys(cryfind_raw, unpacked_samples), cryfind_unpacked_raw)
        # All minus filtered
        if args.filter:
            cryfind_complete_filtered = filter_keys(cryfind_complete, exclude_list)

        # Results for non-obfuscated + unpacked
        cryfind_no_obfusc = merge_dicts(filter_keys(cryfind_raw, list(obfuscated)), cryfind_unpacked_raw)
        
        # Results for non-obfuscated + unpacked minus exclude list
        cryfind_no_obfusc_filtered = {}
        if args.filter:
            cryfind_no_obfusc_filtered = filter_keys(cryfind_no_obfusc, exclude_list)

    non_obfuscated = [file for file in list_files(args.path) if file not in list(obfuscated)]
    all_filtered = [file for file in list_files(args.path) if file not in list(exclude_list)]
    non_obfuscated_filtered = [file for file in non_obfuscated if file not in list(exclude_list)]
    print_stats(total_files, len(list(obfuscated)), len(packed_samples), len(non_obfuscated))
    
    # Results processing from yara
    if args.tool == 'all' or args.tool == 'yara':

        # All with unpacking
        all_yara = process_results(yara_complete, {})
        all_yara['Total'] = total_files
        all_yara['Total found'] = len(yara_complete)
        results["all_yara"] = all_yara
        print_results(all_yara, "All yara")

        free_y = process_results(yara_no_obfusc, {})
        free_y['Total found'] = len(yara_no_obfusc)
        free_y['Total'] = len(non_obfuscated) + len(unpacked_samples)
        results["non-obfuscated_yara"] = free_y
        print_results(free_y, "Yara, Without obfuscation + unpacked")

        if args.filter:
            all_yara_filtered = process_results(yara_complete_filtered, {})
            all_yara_filtered['Total found'] = len(yara_complete_filtered)
            all_yara_filtered['Total'] = len(all_filtered)
            results['all_filtered_yara'] = all_yara_filtered
            print_results(all_yara_filtered, "All, yara, filtered")

            free_yara_filtered = process_results(yara_no_obfusc_filtered, {})
            free_yara_filtered['Total found'] = len(yara_no_obfusc_filtered)
            free_yara_filtered['Total'] = len(non_obfuscated_filtered)
            results['non-obfuscated_filtered_yara'] = free_yara_filtered
            print_results(free_yara_filtered, "Yara, Without obfuscation + unpacked")

    # Cryfind results processing
    if args.tool == 'all' or args.tool == 'cryfind':

        all_cryfind = process_results(cryfind_complete, {})
        all_cryfind["Total"] = total_files
        all_cryfind['Total found'] = len(cryfind_complete)
        results["all_cryfind"] = all_cryfind
        print_results(all_cryfind, "All cryfind")

        free_c = process_results(cryfind_no_obfusc, {})
        free_c["Total"] = len(non_obfuscated) + len(unpacked_samples)
        free_c['Total found'] = len(cryfind_no_obfusc)
        results["non-obfuscated_cryfind"] = free_c
        print_results(free_c, "Cryfind, Without obfuscation + unpacked")

        if args.filter:

            all_cryfind_filtered = process_results(cryfind_complete_filtered, {})
            all_cryfind_filtered['Total found'] = len(cryfind_complete_filtered)
            all_cryfind_filtered['Total'] = len(all_filtered)
            results['filtered_cryfind'] = all_cryfind_filtered
            print_results(all_cryfind_filtered, "All cryfind, filtered")

            free_cryfind_f = process_results(cryfind_no_obfusc_filtered, {})
            free_cryfind_f['Total found'] = len(cryfind_no_obfusc_filtered)
            free_cryfind_f['Total'] = len(non_obfuscated_filtered)
            results['non-obfuscated_filtered_cryfind'] = free_cryfind_f
            print_results(free_cryfind_f, "Cryfind, Without obfuscation + unpacked")
    
    # Combine and process results from all tools
    if args.tool == 'all':

        combined_results = process_results(yara_complete, cryfind_complete)
        print_results(combined_results, "All")
        combined_results["Total"] = total_files
        # Let's limit total found results only to selected algorithms
        combined_results['Total found'] = len(filter_values(merge_dicts(yara_complete, cryfind_complete), ['AES', 'DES', 'Blowfish', 'RSA', 
        'Encryption functions', 'Hashing functions', 'SHA1', 'SHA224', 'SHA256', 'SHA512', 'MD5']))
        results["all"] = combined_results

        free = process_results(yara_no_obfusc, cryfind_no_obfusc)
        free["Total"] = len(non_obfuscated) + len(unpacked_samples)
        free['Total found'] = combined_len(yara_no_obfusc, cryfind_no_obfusc)
        results["all_non-obfuscated"] = free
        print_results(free, "All, Without obfuscation + unpacked")

        # Combined (filtered)
        if args.filter:

            combined_results_filtered = process_results(yara_complete_filtered, cryfind_complete_filtered)
            combined_results_filtered['Total found'] = combined_len(yara_complete_filtered, cryfind_complete_filtered)
            combined_results_filtered['Total'] = len(all_filtered)
            results['all_filtered'] = combined_results_filtered
            print_results(combined_results_filtered, "All, filtered")

            combined_free_filtered = process_results(yara_no_obfusc_filtered, cryfind_no_obfusc_filtered)
            combined_free_filtered['Total found'] = combined_len(yara_no_obfusc_filtered, cryfind_no_obfusc_filtered)
            combined_free_filtered['Total'] = len(non_obfuscated_filtered)
            results['non-obfuscated_filtered'] = combined_free_filtered
            print_results(combined_free_filtered, "All, Without obfuscation + unpacked")

    #print(results)

    if args.save:
        json_object = json.dumps(results, indent=4)
        save_path = os.path.join(results_path, analysis_dirname + "_results.json")
        save_results(save_path, json_object)

if __name__ == "__main__":
    main()