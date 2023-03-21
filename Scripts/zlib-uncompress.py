#!/usr/bin/python
import zlib
import os
import sys, getopt

#directory = '/home/kali/Downloads/mlaware/ransomware'
#outdir = '/home/kali/Documents/Samples/ransomware'
# Usage: $ python zlib-uncompress.py -i dir_with_compressed_samples -o output_dir

def uncompress(inf, outf):
    for filename in os.listdir(inf):
        f = os.path.join(inf, filename)
        of = os.path.join(outf, filename)
        # checking if it is a file
        if os.path.isfile(f):
            try:
                fstream = open(f, 'rb')
                decompressed = zlib.decompress(fstream.read())
                out = open(of, 'wb')
                out.write(decompressed)
                #print(filename)
            except:
                print(filename + " decompression failed")

def main(argv):
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print('zlib-uncompress.py -i <inputfolder> -o <outputfolder>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('zlib-uncompress.py -i <inputfolder> -o <outputfolder>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
    print('Input folder is "', inputfile)
    print('Output folder is "', outputfile)
    if not(inputfile == '') and not(outputfile == ''):
        uncompress(inputfile, outputfile)
    else:
        print("The path is empty")

if __name__ == "__main__":
   main(sys.argv[1:])