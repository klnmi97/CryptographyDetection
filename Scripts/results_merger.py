#!/usr/bin/env python
""" Merges results stored in json files in
case the analysis was done in batches. 
"""

import json
import argparse

def merge_dictionaries(file_paths, show_freqs):
    result_dict = {}

    for file_path in file_paths:
        with open(file_path, 'r') as file:
            data = json.load(file)

        for key, inner_dict in data.items():
            if key in result_dict:
                for inner_key, inner_value in inner_dict.items():
                    if inner_key in result_dict[key]:
                        result_dict[key][inner_key] += inner_value
                    else:
                        result_dict[key][inner_key] = inner_value
            else:
                result_dict[key] = inner_dict
    if show_freqs:
        for key, inner_dict in result_dict.items():
            for inner_key, inner_value in inner_dict.items():
                if inner_key != 'Total':
                    result_dict[key][inner_key] = inner_value / inner_dict['Total'] * 100

    return result_dict

def main():
    parser = argparse.ArgumentParser(description="Process files and display results")
    parser.add_argument("files", nargs="+", help="List of files to process")
    parser.add_argument("-p", "--percents", action="store_true", help="Display results as percents.")

    args = parser.parse_args()

    file_paths = args.files
    show_freqs = args.percents

    merged_dict = merge_dictionaries(file_paths, show_freqs)
    formatted_json = json.dumps(merged_dict, indent=2)
    # Print the resulting merged dictionary
    print(formatted_json)

if __name__ == "__main__":
    main()