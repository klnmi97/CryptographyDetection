import os
import glob
import json
import sqlite3
import subprocess
# debug
import pickle
# end debug

# debug
def load_from_cache(variable_name):
    cache_file = f"{variable_name}.cache"
    if os.path.isfile(cache_file):
        with open(cache_file, "rb") as f:
            return pickle.load(f)
    return None

def cache_list_to_disk(variable_name, data):
    with open(f"{variable_name}.cache", "wb") as f:
        pickle.dump(data, f)

# end debug

def build_shell_command(command, arguments_list: list()):
    separator = " "
    args = separator.join(arguments_list)
    return command + " " + args

def detect_packers(path):
    """ Try to detect packers using Detect It Easy
    commandline tool. 
    Requires diec command line tool. """
    files = glob.glob(path + "/*")
    output = {}

    for filepath in files:
        if os.path.isfile(filepath):
            basename = os.path.basename(filepath)

            args = []
            args.append("-j")
            args.append(filepath)
            cmd = build_shell_command("diec", args)
            output[basename] = os.popen(cmd).read()
    return output

def parse_diec_output(data: dict()):
    parsed_data = {}
    packers = {}
    packer_names = {}
    packed_samples = []

    for hash, block in data.items():
        if not block:
            continue
        parsed_data[hash] = json.loads(block)

    for key, value in parsed_data.items():
        for detect in value['detects']:
            if 'values' in detect:
                for packer_info in detect['values']:
                    # TODO: what if there are several packers/SFX?
                    if packer_info['type'] == 'Packer':
                        packer_names[key] = packer_info['name']
                        packed_samples.append(key)
                    elif packer_info['type'] == 'SFX':
                        packer_names[key] = 'SFX'

    #print(packer_names)
    #print(f"Total packed files: {len(packer_names)}")
    #print(f"SFXed files: {sfx}")

    for hash, packer in packer_names.items():

        if packer in packers.keys():
            packers[packer] += 1
        else:
            packers[packer] = 1

    for packer, quantity in packers.items():
        print(f"{packer}: {quantity}")

    return packer_names
    
    
def filter_packer(packed_samples: dict(), filter: str, full_path = "") -> list():
    return [os.path.join(full_path, key) for key, value in packed_samples.items() if value == filter]

def unpack_unipack(path, samples: list(), debug = False):

    # Create directory for unpacked samples
    output_dir = os.path.join(path, "unpacked/")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Call unipacker for each sample
    for sample in samples:
        sample_path = os.path.join(path, sample)

        args = []
        args.append("-d")
        args.append(output_dir)
        args.append(sample_path)
        cmd = build_shell_command("unipacker", args)
        #output = os.popen(cmd).read()
        try:
            check_output(cmd, timeout=5, shell=True)
        except:
            print(f"{sample} unpacking timeouted")
        #if debug:
        #    print(output)

    return output_dir

def unpack_upx(path, samples: list()) -> str:
    successful_calls = 0
    # Create directory for unpacked samples
    output_dir = os.path.join(path, "unpacked/")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Call upx for each sample
    for sample in samples:
        sample_path = os.path.join(path, sample)
        unpacked_sample_path = os.path.join(output_dir, sample)

        args = []
        args.append("-d")
        args.append("-o")
        args.append(unpacked_sample_path)
        args.append(sample_path)
        cmd = build_shell_command("upx", args)
        result = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            successful_calls += 1
    print(f"Successfully unpacked {successful_calls} samples out of {len(samples)}")
    return output_dir

def check_packers_db(path_to_db, list):
    """ List packed files based on the SOREL database file. """
    # Counters
    total_files = 0
    packed_files = []

    # Set up database connection
    conn = sqlite3.connect("/home/kali/Downloads/mlaware/meta.db")
    cursor = conn.cursor()

    # Get list of files in directory
    #dir_path = '/home/kali/Documents/Samples/malware'
    files = os.listdir(list)

    # Loop through files and query database
    for file_name in files:
        if os.path.isfile(os.path.join(list, file_name)):
            total_files += 1
            # Construct SQL query using file name
            query = f'SELECT packed FROM meta WHERE sha256="{file_name}"'
            cursor.execute(query)

            # Process query results
            result = cursor.fetchone()
            if result[0] and result[0] > 0:
                packed_files.append(file_name)

    # Close database connection
    conn.close()

    #print(f"Total files: {total_files}, packed files: {packed_files}, which is {packed_files / total_files * 100}")
    return(packed_files)


def analyze(path: str, exclude = list()):
    """ Runs Detect It Easy on the folder of samples
    to detect packers. Parses raw results and returns
    a dictionary of samples and the used packers. """
    packed_samples = []
    # Cache to save time. TODO: remove for final solution
    packed_samples = load_from_cache("packed_samples")
    result = load_from_cache("packers")

    if not result:
        result = detect_packers(path)
        cache_list_to_disk("packers", result)
    
    packed_samples = parse_diec_output(result)
    cache_list_to_disk("packed_samples", packed_samples)
    
    return packed_samples

def unpack(path, sample_list):

    upx = filter_packer(sample_list, "UPX")
    unpacked_path = unpack_upx(path, upx)

    return unpacked_path
    #unpack("/home/kali/Documents/Samples/malware_nocompression/", ["7bd45c7bf1b6b211ba04acd289b7e3bc7f4b2d529afe8c2ba2f8aed83058fa0e"])
    # # Check packers in DB
    # packed_db = check_packers_db("", "/home/kali/Documents/Samples/malware_nocompression")

    # count = 0
    # for element, value in packed_samples.items():
    #     if element in packed_db:
    #         count += 1

    # print(f"{count} elements from list1 are in list2.")

#out = "/home/kali/Documents/Workspace/subsetNormal-packers-info.json"
#samples_folder = "/home/kali/Documents/Samples/malware_nocompression/"


#info = analyze(samples_folder)

#upx = [key for key, value in packed_samples.items() if value == 'UPX']
#unpack_upx("/home/kali/Documents/Samples/malware_nocompression/", upx)

#other = [item for item, value in packed_samples.items() if item not in upx]

#packed = list(set(packed_samples + packed_db))
#packed = packed_samples
#unpack("/home/kali/Documents/Samples/malware_nocompression/", packed, True)

#import yara_analyzer

#pathlist = [os.path.join("/home/kali/Documents/Samples/malware_nocompression/", sample) for sample in upx]


#print('')