import yaml
import re

yaml_file = open("functions_filter.yaml", 'r')
yaml_content = yaml.load(yaml_file)

def process(obj):
    if isinstance(obj, list):
        return [rule for rule in obj]

def find_all_matches(source, pattern):
    return re.findall(pattern, source)

filters = {}
for key, value in yaml_content.items():
    filters[key] = process(value)
    #print(filters[key])

file_path = "/home/kali/Downloads/strings_result/MSIL_Filecoder.UK.txt"

with open(file_path) as f:
    lines = f.read()
    for pattern in filters["Crypto"]:
        print(find_all_matches(lines, pattern))