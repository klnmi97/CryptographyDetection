#!/usr/bin/env python
""" Script to handle SoReL-20M dataset and its parst. 

    Usage: dataset_manager.py -h 
"""

import argparse
import os
import random
import boto3
import botocore
from botocore.config import Config
from botocore import UNSIGNED
import sqlite3
import sys
import zlib
import pefile
import threading
import numpy as np


def write_chunks_to_files(lst, n, path):
    """ Divide the provided list into n chunks and write
    them into n files to the provided path. """

    # Divide list into chunks of size n
    chunks = [lst[i:i+n] for i in range(0, len(lst), n)]
    
    # Write each chunk to a separate file
    for i, chunk in enumerate(chunks):
        filename = "samples_{}.list".format(i)
        filepath = os.path.join(path, filename)
        with open(filepath, "w") as f:
            #f.write('\n'.join(chunk))
            for item in chunk:
                f.write("%s\n" % item)

def read_file(path) -> list:
    """ Read the provided file into a list. """
    if os.path.isfile(path):
        with open(path, 'r') as f:
            lines = [line.strip() for line in f]
        return lines
    else:
        print(f"Error: {path} file does not exist or is not a file!")
        sys.exit(1)

def create_sample_set(dp_path, n='all', category='is_malware'):
    """ Create a set of files based on the provided arguments.
    Arguments:
        dp_path: path of the meta.db file from the SoReL-20M repo.
        n: size of the resulting set. Default is ALL.
        category: malware category. Should be on of the categories 
        from the meta.db file. The default is is_malware which means
        any malware sample can be chosen. 
    Return:
        set of sample names. """
    sample_ids = []
    sample_sha256 = []
    samples_len = 0
    resulting_set = []

    conn = sqlite3.connect(dp_path)
    cursor = conn.cursor()
    cursor.execute("SELECT sha256 FROM meta WHERE %s >= 1" % category)
    result = cursor.fetchall()

    for row in result:
        sample_sha256.append(row[0])

    if n != 'all':
        samples_len = len(sample_sha256)
        if n >= samples_len:
             raise Exception("Cannot generate a sample list larger than samples available")

        i = 0
        while i < n:
            r = random.SystemRandom().randint(0, samples_len - 1)
            if not r in sample_ids:
                sample_ids.append(r)
                resulting_set.append(sample_sha256[r])
                i += 1

        print("Shuffle done")
    else:
        resulting_set = sample_sha256
    
    return resulting_set

def download_sample(download_path, list, s3, thread=0):
    """ Download samples listed in the provided list.
    
    Arguments:
        download_path: path where to save zipped samples.
        list: list with sample names to download.
        s3: s3 client instance.
        thread: thread number for output info."""
    filecount = 0

    for file in list:
        output_path = os.path.join(download_path, file)
        try:
            s3.download_file('sorel-20m', "09-DEC-2020/binaries/" + file, output_path)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                print("The object does not exist")
            else:
                raise
        filecount += 1
        print(f"[Thread {thread}] Files requested: {filecount}")

def download_samples(download_path, lst):
    """ Download samples in parallel.
        
        Arguments:
            download_path: path to download zipped samples.
            lst: list of samples to download. """
    threads = []
    n = 10
    s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))

    if len(lst) > 10:
        lists = list(np.array_split(lst, n))
        for i in range(n):
            t = threading.Thread(target=download_sample, args=(download_path, lists[i], s3, i))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
    else:
        download_sample(download_path, lst, s3)

def decompress(path, output_path):
    """ Decompress downloaded samples with zlib.
        Arguments:
            path: directory with compressed samples.
            output_path: directory where to save
            decompressed samples. """
    for filename in os.listdir(path):
            f = os.path.join(path, filename)
            of = os.path.join(output_path, filename)
            # checking if it is a file
            if os.path.isfile(f):
                try:
                    fstream = open(f, 'rb')
                    decompressed = zlib.decompress(fstream.read())
                    out = open(of, 'wb')
                    out.write(decompressed)
                except:
                    print(filename + " decompression failed")

def restore_header(filename):
    """ Restore file header bytes. """
    # Load the PE file
    pe = pefile.PE(filename)

    # Set IMAGE_FILE_HEADER.Machine to i386 (0x014c)
    pe.FILE_HEADER.Machine = 0x014c

    # Set IMAGE_OPTIONAL_HEADER.Subsystem to WINDOWS_CUI (0x03)
    pe.OPTIONAL_HEADER.Subsystem = 0x03

    # Write the changes back to the file
    pe.write(filename)

def restore_headers(path):
    """ Restore headers of the files located
        in the provided directory. """
    if os.path.isdir(path):
            # Handle the folder here.
            print(f"Restoring header bytes for {path}")
            for file_name in os.listdir(path):
                file_path = os.path.join(path, file_name)
                if os.path.isfile(file_path):
                    # Handle the file here.
                    restore_header(file_path)
                else:
                    pass
    else:
        print(f"Error: {path} is not a directory.")

if __name__ == '__main__':

    category = 'is_malware'
    samples = 'all'
    metadb_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'meta.db')
    decompressed_path=''
    gen_quantity = 0
    batches = 1

    parser = argparse.ArgumentParser(description='Download and modify malware samples.')
    parser.add_argument('path', type=str, help='path where to download the malware samples from S3 or save the sample list.')
    parser.add_argument('-n', '--num_samples', type=int, help='Number of samples to download randomly')
    parser.add_argument('-g', '--gen_list', nargs=2, type=int, metavar=('quantity', 'size'), help='Generate a random list of samples and save into files using the provided path. Can be used together with the category argument.')
    parser.add_argument('-c', '--category', type=str, help='Category of malware to download. See categories at https://ai.sophos.com/2020/12/14/sophos-reversinglabs-sorel-20-million-sample-malware-dataset/')
    parser.add_argument('-d', '--decompress', type=str, help='Path where to store decompressed samples')
    parser.add_argument('-r', '--restore', action='store_true', help='restore header bytes')
    parser.add_argument('-f', type=str, dest='file', metavar='file', help='Download samples listed in the provided file')
    args = parser.parse_args()

    # Download meta.db file if it was not found.
    if not os.path.isfile(metadb_path):
        print("Downloading meta.db database for SoReL-20M")
        s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        try:
            s3.download_file('sorel-20m', "09-DEC-2020/binaries/processed-data/meta.db", metadb_path)
        except botocore.exceptions.ClientError as e:
            print("Error downloading meta.db. You can download it manually from s3://sorel-20m/09-DEC-2020/processed-data/meta.db and place it into the directory with this script.")
            sys.exit()

    if args.category:
        category = args.category

    if args.num_samples:
        samples = args.num_samples

    if args.gen_list:
        samples, batches = args.gen_list

    if args.decompress:
        decompressed_path = args.decompress

    if args.file:
        samples_list = read_file(args.file)
    else:
        samples_list = create_sample_set(metadb_path, samples, category)
    
    # If option -g is active, create we write the generated list and exit
    if args.gen_list:
        write_chunks_to_files(samples_list, batches, args.path)
        sys.exit(0)

    download_samples(args.path, samples_list)
    # Decompress samples and restore headers if requested.
    if args.decompress:
        decompress(args.path, decompressed_path)
        if args.restore:
            restore_headers(decompressed_path)