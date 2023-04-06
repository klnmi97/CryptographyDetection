import argparse
import os
import random
import boto3
import botocore
from botocore.config import Config
from botocore import UNSIGNED
import sqlite3
import sys


def get_samples_from_file(path):
    with open(path, 'r') as file:
        lines = file.readlines()
    return [line.strip() for line in lines]

def create_sample_set(dp_path, n='all', category='is_malware'):

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

def download_samples(download_path, list):
    filecount = 0
    s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))

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
        print("Files requested:", filecount)
    

if __name__ == '__main__':

    category = 'is_malware'
    samples = 'all'
    metadb_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'meta.db')

    parser = argparse.ArgumentParser(description='Download and modify malware samples.')
    parser.add_argument('path', type=str, help='path where to download the malware samples from S3')
    parser.add_argument('-n', '--num_samples', type=int, help='Number of samples to download randomly')
    parser.add_argument('-c', '--category', type=str, help='Category of malware to download. See categories at https://ai.sophos.com/2020/12/14/sophos-reversinglabs-sorel-20-million-sample-malware-dataset/')
    parser.add_argument('-H', '--header', action='store_true', help='restore header bytes')
    args = parser.parse_args()

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

    samples_list = create_sample_set(metadb_path, args.num_samples, category)
    

    download_samples(args.path, samples_list)