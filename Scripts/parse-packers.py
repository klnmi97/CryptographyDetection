# import re

# # Define regular expression patterns to match hash, format, and packer lines
# hash_pattern = r'(^[a-fA-F0-9]{64}$)'
# packer_pattern = r'.*\bPacker\b. ([^[]*)'
# packer_name_pattern = r'(.*)\('

# # Initialize counters
# total_files = 0
# packed_files = 0
# packed_samples = {}
# packers = {}

# # Open input file for reading
# with open('/home/kali/Documents/Workspace/subsetNormal-packers-info.txt', 'r') as f:

#     # Initialize variables to store hash and format
#     current_hash = ''
    
#     # Loop over lines in file
#     for line in f:
        
#         # Try to match hash and format patterns
#         match = re.match(hash_pattern, line)
#         if match:
#             current_hash = match.group(1)
#             total_files += 1
#             continue
        
#         # Try to match packer pattern
#         match = re.match(packer_pattern, line)
#         if match:
#             detected_packer = match.group(1)
#             # Add packer to dictionary and increment count
#             packed_files += 1
#             packed_samples[current_hash] = detected_packer


# for hash, packer in packed_samples.items():

#     match = re.match(packer_name_pattern, packer)
#     if match:
#         packer_name = match.group(1)
#         if packer_name in packers.keys():
#             packers[packer_name] += 1
#         else:
#             packers[packer_name] = 1


# # Print results
# print(f'Total files: {total_files}')
# print(f'Packed files: {packed_files}')
# print('Packer statistics:')
# for packer, quantity in packers.items():
#     print(f"{packer}: {quantity}")
# #for sample, packer in packed_samples.items():
# #    print(f"{sample}: {packer}")

import json
import matplotlib.pyplot as plt

packers = {}
sfx = 0

with open('/home/kali/Documents/Workspace/subsetNormal-packers-info.json') as f:
    data = f.read()

parsed_data = {}
for block in data.split('\n\n\n'):
    if not block:
        continue
    key, value = block.split('\n', 1)
    parsed_data[key] = json.loads(value)

packer_names = {}
for key, value in parsed_data.items():
    for detect in value['detects']:
        if 'values' in detect:
            for packer_info in detect['values']:
                if packer_info['type'] == 'Packer':
                    packer_names[key] = packer_info['name']
                elif packer_info['type'] == 'SFX':
                    sfx += 1

#print(packer_names)
print(f"Total packed files: {len(packer_names)}")
print(f"SFXed files: {sfx}")

for hash, packer in packer_names.items():

    if packer in packers.keys():
        packers[packer] += 1
    else:
        packers[packer] = 1

for packer, quantity in packers.items():
     print(f"{packer}: {quantity}")
