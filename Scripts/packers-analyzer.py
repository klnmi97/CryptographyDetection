import os
import glob
import json

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
    sfx = 0

    for hash, block in data.items():
        if not block:
            continue
        parsed_data[hash] = json.loads(block)

    for key, value in parsed_data.items():
        for detect in value['detects']:
            if 'values' in detect:
                for packer_info in detect['values']:
                    if packer_info['type'] == 'Packer':
                        packer_names[key] = packer_info['name']
                        packed_samples.append(key)
                    elif packer_info['type'] == 'SFX':
                        sfx += 1

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

    return packed_samples
    
    
def unpack(path, samples: list(), debug = False):

    # Create directory for unpacked samples
    output_dir = os.path.join(path, "unpacked")
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
        output = os.popen(cmd).read()
        if debug:
            print(output)

    return output_dir

#out = "/home/kali/Documents/Workspace/subsetNormal-packers-info.json"
#samples_folder = "/home/kali/Documents/Samples/malware_nocompression"
#result = detect_packers(samples_folder)

#packed_samples = parse_diec_output(result)

#unpack("/home/kali/Documents/Samples/malware_nocompression/", ["7bd45c7bf1b6b211ba04acd289b7e3bc7f4b2d529afe8c2ba2f8aed83058fa0e"])