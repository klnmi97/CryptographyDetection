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
    files_set = set()
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):
            files_set.add(file_name)
    return files_set

def count_files(path):
    file_count = 0
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            file_count += 1
    return file_count

def save_results(path: str, data):
    with open(path, 'w') as f:
        f.write(data)

def read_file(path) -> list:
    if os.path.isfile(path):
        with open(path, 'r') as f:
            lines = [line.strip() for line in f]
        return lines
    else:
        print(f"Error: {path} file does not exist or is not a file!")
        sys.exit(1)

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

def filter_values(dict1: dict, filter: list)-> dict:
    return {key: value for key, value in dict1.items() if any(item in value for item in filter)}

def filter_keys(dict1: dict, exclude: list)-> dict:
    return {key: dict1[key] for key in dict1 if key not in exclude}

def collect_keys(dict1: dict, include: list)-> dict:
    return {key: dict1[key] for key in dict1 if key in include}

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

def combined_len(dict1, dict2):
    return len(set(dict1.keys()).union(set(dict2.keys())))

def print_results(data, tool_name):
    print('--------------------------------------------')
    print(f"Results after analysis with {tool_name}:")
    print('--------------------------------------------')
    # for rule in data:
    #     print(f"{rule}: {data[rule]}")
    print(data) 
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

    # Analyze or/and unpack
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


    if args.tool == 'all' or args.tool == 'yara':

        tool_name = "yara"
        cache_file_yara = analysis_dirname + "_" + tool_name
        if args.cache:
            yara_unpacked_result = packing_analyzer.load_from_cache(cache_file_yara + "_u")
            yara_result = packing_analyzer.load_from_cache(cache_file_yara)
        if not yara_unpacked_result or not yara_result:
            # Run yara
            with timer():
                yara_unpacked_result = yara_analyzer.run(unpacked_path)
                yara_result = yara_analyzer.run(args.path)
            
            if args.cache:
                packing_analyzer.cache_data_to_disk(cache_file_yara + "_u", yara_unpacked_result)
                packing_analyzer.cache_data_to_disk(cache_file_yara, yara_result)

        # Results for all samples: all + unpacked    
        yara1 = merge_dicts(filter_keys(yara_result, unpacked_samples), yara_unpacked_result)

        # All minus filtered
        if args.filter:
            yara1_f = filter_keys(yara1, exclude_list)

        # Results for non-obfuscated samples
        yara2 = filter_keys(yara_result, list(obfuscated))
        # Results for all but packed samples
        yara3 = filter_keys(yara_result, packed_samples.keys())
        # Results for packed only + unpacked packed
        yara4 = merge_dicts(filter_keys(collect_keys(yara_result, packed_samples), unpacked_samples), yara_unpacked_result)
        # Results for non-obfuscated + unpacked
        yara5 = merge_dicts(filter_keys(yara_result, list(obfuscated)), yara_unpacked_result)

        # Results for non-obfuscated + unpacked minus exclude list
        yara5_f = {}
        if args.filter:
            yara5_f = filter_keys(yara5, exclude_list)

    if args.tool == 'all' or args.tool == 'cryfind':
        # Run cryfind
        tool_name = "cryfind"
        cache_file_cryfind = analysis_dirname + "_" + tool_name
        cryfind_unpacked_result = packing_analyzer.load_from_cache(cache_file_cryfind + "_u")
        cryfind_result = packing_analyzer.load_from_cache(cache_file_cryfind)
        if not cryfind_unpacked_result or not cryfind_result:

            unpacked_result = {}
            with timer():
                cryfind_unpacked_result = cryfind_analyzer.run(unpacked_path)
                cryfind_result = cryfind_analyzer.run(args.path)

            if args.cache:
                packing_analyzer.cache_data_to_disk(cache_file_cryfind + "_u", cryfind_unpacked_result)
                packing_analyzer.cache_data_to_disk(cache_file_cryfind, cryfind_result)
        
        # Results for all samples: all + unpacked
        cryfind1 = merge_dicts(filter_keys(cryfind_result, unpacked_samples), cryfind_unpacked_result)
        # All minus filtered
        if args.filter:
            cryfind1_f = filter_keys(cryfind1, exclude_list)

        # Results for non-obfuscated samples
        cryfind2 = filter_keys(cryfind_result, list(obfuscated))
        # Results for all but packed samples
        cryfind3 = filter_keys(cryfind_result, packed_samples.keys())
        # Results for packed only + unpacked packed
        cryfind4 = merge_dicts(filter_keys(collect_keys(cryfind_result, packed_samples), unpacked_samples), cryfind_unpacked_result)
        # Results for non-obfuscated + unpacked
        cryfind5 = merge_dicts(filter_keys(cryfind_result, list(obfuscated)), cryfind_unpacked_result)
        
        # Results for non-obfuscated + unpacked minus exclude list
        cryfind5_f = {}
        if args.filter:
            cryfind5_f = filter_keys(cryfind5, exclude_list)

    print("Total files:", total_files)
    print("Total obfuscated:", len(list(obfuscated)))
    print("Total packed:", len(packed_samples))
    non_obfuscated = [file for file in list_files(args.path) if file not in list(obfuscated)]
    print("Total non-obfuscated:", len(non_obfuscated))
    all_filtered = [file for file in list_files(args.path) if file not in list(exclude_list)]
    non_obfuscated_filtered = [file for file in non_obfuscated if file not in list(exclude_list)]
   
    
    if args.tool == 'all' or args.tool == 'yara':

        # All with unpacking
        all_yara = process_results(yara1, {})
        print_results(all_yara, "All yara")
        all_yara["Total"] = total_files
        all_yara['Total found'] = len(yara1)
        results["all_yara"] = all_yara

        free_y = process_results(yara5, {})
        free_y['Total found'] = len(yara5)
        free_y['Total'] = len(non_obfuscated) + len(unpacked_samples)
        results["non-obfuscated_yara"] = free_y
        print_results(free_y, "Yara, Without obfuscation + unpacked")

        if args.filter:
            all_yara_f = process_results(yara1_f, {})
            all_yara_f['Total found'] = len(yara1_f)
            all_yara_f['Total'] = len(all_filtered)
            results['all_filtered_yara'] = all_yara_f
            print_results(all_yara_f, "All, yara, filtered")

            free_yara_f = process_results(yara5_f, {})
            free_yara_f['Total found'] = len(yara5_f)
            free_yara_f['Total'] = len(non_obfuscated_filtered)
            results['non-obfuscated_filtered_yara'] = free_yara_f
            print_results(free_yara_f, "Yara, Without obfuscation + unpacked")


    if args.tool == 'all' or args.tool == 'cryfind':

        all_cryfind = process_results(cryfind1, {})
        print_results(all_cryfind, "All cryfind")
        all_cryfind["Total"] = total_files
        all_cryfind['Total found'] = len(cryfind1)
        results["all_cryfind"] = all_cryfind

        free_c = process_results(cryfind5, {})
        free_c["Total"] = len(non_obfuscated) + len(unpacked_samples)
        free_c['Total found'] = len(cryfind5)
        results["non-obfuscated_cryfind"] = free_c
        print_results(free_c, "Cryfind, Without obfuscation + unpacked")

        if args.filter:

            all_cryfind_f = process_results(cryfind1_f, {})
            all_cryfind_f['Total found'] = len(cryfind1_f)
            all_cryfind_f['Total'] = len(all_filtered)
            results['filtered_cryfind'] = all_cryfind_f
            print_results(all_cryfind_f, "All cryfind, filtered")

            free_cryfind_f = process_results(cryfind5_f, {})
            free_cryfind_f['Total found'] = len(cryfind5_f)
            free_cryfind_f['Total'] = len(non_obfuscated_filtered)
            results['non-obfuscated_filtered_cryfind'] = free_cryfind_f
            print_results(free_cryfind_f, "Cryfind, Without obfuscation + unpacked")

    if args.tool == 'all':

        combined_results = process_results(yara1, cryfind1)
        print_results(combined_results, "All")
        combined_results["Total"] = total_files
        #combined_results['Total found'] = combined_len(yara1, cryfind1)
        combined_results['Total found'] = len(filter_values(merge_dicts(yara1, cryfind1), ['AES', 'DES', 'Blowfish', 'RSA', 
        'Encryption functions', 'Hashing functions', 'SHA1', 'SHA224', 'SHA256', 'SHA512', 'MD5']))
        results["all"] = combined_results

        free = process_results(yara5, cryfind5)
        free["Total"] = len(non_obfuscated) + len(unpacked_samples)
        free['Total found'] = combined_len(yara5, cryfind5)
        results["all_non-obfuscated"] = free
        print_results(free, "All, Without obfuscation + unpacked")

        # Combined (filtered)
        if args.filter:

            combined_results_f = process_results(yara1_f, cryfind1_f)
            combined_results_f['Total found'] = combined_len(yara1_f, cryfind1_f)
            combined_results_f['Total'] = len(all_filtered)
            results['all_filtered'] = combined_results_f
            print_results(combined_results_f, "All, filtered")

            free_f = process_results(yara5_f, cryfind5_f)
            free_f['Total found'] = combined_len(yara5_f, cryfind5_f)
            free_f['Total'] = len(non_obfuscated_filtered)
            results['non-obfuscated_filtered'] = free_f
            print_results(free_f, "All, Without obfuscation + unpacked")


    # Without obfuscation
    # unencrypted_y = process_results(yara2, {})
    # print_results(unencrypted_y, "Yara, not obfuscated")

    # unencrypted_c = process_results(cryfind2, {})
    # print_results(unencrypted_c, "Cryfind, not obfuscated")

    # unencrypted = process_results(yara2, cryfind2)
    # print_results(unencrypted, "All, not obfuscated")

    # Without packers only
    # without_packing_y = process_results(yara3, {})
    # print_results(without_packing_y, "Yara, Without packing or detected protectors/SFXs")

    # without_packing_c = process_results(cryfind3, {})
    # print_results(without_packing_c, "Cryfind, Without packing or detected protectors/SFXs")

    # without_packing = process_results(yara3, cryfind3)
    # print_results(without_packing, "Without packing or detected protectors/SFXs")

    # Packed only + unpacked
    # packed_results_y = process_results(yara4, {})
    # print_results(packed_results_y, "Yara, packed only")

    # packed_results_c = process_results(cryfind4, {})
    # print_results(packed_results_c, "Cryfind, packed only")

    # packed_results = process_results(yara4, cryfind4)
    # print_results(packed_results, "All, packed only")

    print(results)

    if args.save:
        json_object = json.dumps(results, indent=4)
        save_path = os.path.join(results_path, analysis_dirname + "_results.json")
        save_results(save_path, json_object)

if __name__ == "__main__":
    main()