# CryptographyDetection
Repository to the thesis "Detecting cryptographic primitives in malicious Windows binaries"

## Prerequisites

- Python 3.8 - you can use pyenv (https://www.kali.org/docs/general-use/using-eol-python-versions/)
- Install requirements

  You can use requirements.txt or the list below:
    - boto3
    - pefile
    - numpy
    - yara-python

- Install cryfind so that the pipeline will be able to use crylib

  Use: `pip install git+https://github.com/oalieno/cryfind.git`

  More information: https://github.com/oalieno/cryfind

- Install Detect It Easy

  You can use the following commands:
  ```
  sudo apt install qtbase5-dev qtscript5-dev qttools5-dev-tools git build-essential qtchooser
  git clone --recursive https://github.com/horsicq/DIE-engine
  cd DIE-engine
  bash -x build_dpkg.sh
  sudo dpkg -i release/die_*.deb
  ```
  or visit https://github.com/horsicq/Detect-It-Easy

## How to reproduce analysis

- Using datataset_manager.py and 10 provided files with randomly selected sample names, download samples. If you decide to analyze them in several batches (e.g. analyze by 20k sets), use different directory names where you store the binaries for each batch. I used 5 batches by 20k samples.

  Using the following command the script will download 10k samples from the samples_0.list to the temp directory, decompress them to the directory called analysis and restore header bytes. Thus the analysis destination for the pipeline script will be the analysis directory. Ideally delete the temp directory afterwards or do not reuse it for the next batches.

  ```python dataset_manager.py -f samples_0.list -d analysis -r temp
     python dataset_manager.py -f samples_1.list -d analysis -r temp1
     python dataset_manager.py -f samples_2.list -d analysis1 -r temp2
     python dataset_manager.py -f samples_3.list -d analysis1 -r temp3
     python dataset_manager.py -f samples_4.list -d analysis2 -r temp4
     python dataset_manager.py -f samples_5.list -d analysis2 -r temp5
     ...
  ```

- After downloading samples you can run the pipeline. You can start several command line windows at a time for different directories.

  ``` python pipeline.py analysis -s results
      python pipeline.py analysis1 -s results
      python pipeline.py analysis2 -s results
  ```

  You can also add `-f droppers.list` to get results without samples marked as droppers and downloaders.

- If you have analyzed in batches and saved the results, you can now merge those results into one output table using results_merger.py.

  ``` python results_merger.py results/analysis_results.json results/analysis1_results.json results/analysis2_results.json results/analysis3_results.json results/analysis4_results.json```

  Use additional `-p` argument to use percents instead of quantities.

  ```python results_merger.py -p results/analysis_results.json results/analysis1_results.json results/analysis2_results.json results/analysis3_results.json results/analysis4_results.json```
