#!/usr/bin/env python
""" Packers and obfuscation analysis script.
    Uses DetectItEasy and UPX.

    Is disigned to be used as a part
    of the pipeline. Use pipeline.py -h.
"""

import os
import glob
import json
import sqlite3
import subprocess
import pipeline_utils

def build_shell_command(command, arguments_list: list()):
    separator = " "
    args = separator.join(arguments_list)
    return command + " " + args

def add_to_dict(dictionary, key, value):
    if key in dictionary:
        dictionary[key].append(value)
    else:
        dictionary[key] = [value]

def detect_packers(path):
    """ Tries to detect packers using Detect It Easy
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

def detect_high_entropy(path):
    """ Detect packed or encrypted files
    based on the file entropy value. Requires
    diec command line tool.
    
    Arguments:
        path: path to the directory with samples

    Return:
        Dictionary with results for each sample
    in json format with file name as key. 
    """

    files = glob.glob(path + "/*")
    output = {}

    for filepath in files:
        if os.path.isfile(filepath):
            basename = os.path.basename(filepath)

            args = []
            args.append("-e")
            args.append("-j")
            args.append(filepath)
            cmd = build_shell_command("diec", args)
            output[basename] = os.popen(cmd).read()
    return output    

def parse_diec_output(data: dict()):
    """ Parse diec output in json format of the 
    analysis using no additional options. """
    parsed_data = {}
    packers = {}
    packed_samples = {}

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
                       #packed_samples[key] = packer_info['name']
                        add_to_dict(packed_samples, key, packer_info['name'])
                    if packer_info['type'] == 'SFX':
                        #packed_samples[key] = 'SFX'
                        add_to_dict(packed_samples, key, 'SFX')
                    if packer_info['type'] == 'Installer':
                        #packed_samples[key] = packer_info['name']
                        add_to_dict(packed_samples, key, packer_info['name'])
                    if packer_info['type'] == 'Protector':
                        #packed_samples[key] = packer_info['name']
                        add_to_dict(packed_samples, key, packer_info['name'])

    for hash, packer_list in packed_samples.items():
        for packer in packer_list:
            if packer in packers.keys():
                packers[packer] += 1
            else:
                packers[packer] = 1

    sorted_packers = sorted(packers.items(), key=lambda x: x[1], reverse=True)
    for packer, quantity in sorted_packers:
        print(f"{packer}: {quantity}")

    return packed_samples
    
def parse_entropy_data(data: dict):
    """ Parses output of the Detect It Easy produced
    with -e argument in json format. Expects dictionary
    where file names are keys and values are represented
    by the results in json format. 
    
    :return total number of files marked as packed
    """
    parsed_data = {}
    result = set()

    for hash, block in data.items():
        if not block:
            continue
        parsed_data[hash] = json.loads(block)

    for key, value in parsed_data.items():
        status = value["status"]
        if status == 'packed':
            result.add(key)
    
    return result

    
def filter_packer(packed_samples: dict(), filter: str, full_path = "") -> list():
    """ Get list of samplest which are using a certain packer. """
    return [os.path.join(full_path, key) for key, value_list in packed_samples.items() if filter in value_list]

def unpack_upx(path, samples: list()) -> str:

    """ Try to unpack samples using upx -d and put 
    the unpacked samplest to the unpacked directory
    in the provided path.
    
    Arguments:
        path: path with samples
        samples: list of samples to unpack 
    Return:
        path to the output directory. 
    """

    successful_calls = 0
    unpacked = []
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
            unpacked.append(sample)
    print(f"Successfully unpacked {successful_calls} samples out of {len(samples)}")
    return output_dir

def analyze_packers(path: str, exclude = list(), use_caching = False):
    """ Run Detect It Easy on the folder of samples
    to detect packers. Parses raw results and returns
    a dictionary of samples and the used packers.
    
    Arguments:
        path: path with samples to process.
        exclude: optional list of file names to exclude
        from analysis. 
        
    Return:
        Dictionary sample - packer
    """
    packed_samples = []
    result = None
    analysis_dirname = os.path.basename(path) + "_packers"
    if use_caching:
        packed_samples = pipeline_utils.load_from_cache(analysis_dirname)
        result = pipeline_utils.load_from_cache(analysis_dirname)

    if not result:
        result = detect_packers(path)
        if use_caching:
            pipeline_utils.cache_data_to_disk(analysis_dirname, result)
    
    packed_samples = parse_diec_output(result)

    return packed_samples

def analyze_entropy(path: str, use_caching = False):
    """ Analyzes packing/encryption based on the
    file entropy.
    
    Arguments:
        path: path to the directory with samples.

    Return:
        list of files detected as "packed" by Detect It Easy """
    
    analysis_dirname = os.path.basename(path) + "_entropy"
    entropy_data = None
    if use_caching:
        entropy_data = pipeline_utils.load_from_cache(analysis_dirname)
    if not entropy_data:
        entropy_data = detect_high_entropy(path)
        if use_caching:
            pipeline_utils.cache_data_to_disk(analysis_dirname, entropy_data)


    return parse_entropy_data(entropy_data)

def unpack(path, sample_list: dict):
    """ Unpack samples. Currently supports
    only UPX.
    
    Arguments:
        path: path to the directory with samples.
        sample_list: dictionary sample-packer obtained from
        the analyze() function.
    Return:
        unpacked_path: directory path with unpacked samples.
        upx: list of samples which were processed. """


    upx = filter_packer(sample_list, "UPX")
    unpacked_path = unpack_upx(path, upx)
    unpacked_samples = os.listdir(unpacked_path)
    # Return new path and list of unpacked samples
    return unpacked_path, unpacked_samples