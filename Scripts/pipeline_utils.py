#!/usr/bin/env python
""" 
    Utils for the pipeline.

    Is disigned to be used as a part
    of the pipeline. Use pipeline.py -h.
"""

import pickle
import os

def load_from_cache(file_name):
    cache_file = f"{file_name}.cache"
    if os.path.isfile(cache_file):
        with open(cache_file, "rb") as f:
            return pickle.load(f)
    return None

def cache_data_to_disk(file_name, data):
    with open(f"{file_name}.cache", "wb") as f:
        pickle.dump(data, f)