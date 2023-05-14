import json

def merge_dictionaries(file_paths):
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

    for key, inner_dict in result_dict.items():
        for inner_key, inner_value in inner_dict.items():
            if inner_key != 'Total':
                result_dict[key][inner_key] = inner_value / inner_dict['Total'] * 100

    return result_dict

# Provide the list of file paths to be read
file_paths = ['results/analysis_results.json', 'results/analysis3_results.json', 'results/analysis5_results.json', 'results/analysis7_results.json', 'results/analysis9_results.json']

# Call the merge_dictionaries function
merged_dict = merge_dictionaries(file_paths)
formatted_json = json.dumps(merged_dict, indent=2)
# Print the resulting merged dictionary
print(formatted_json)