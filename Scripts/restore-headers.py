import argparse
import pefile
import os

def restoreHeader(filename):
    # Load the PE file
    pe = pefile.PE(filename)

    # Set IMAGE_FILE_HEADER.Machine to i386 (0x014c)
    pe.FILE_HEADER.Machine = 0x014c

    # Set IMAGE_OPTIONAL_HEADER.Subsystem to WINDOWS_CUI (0x03)
    pe.OPTIONAL_HEADER.Subsystem = 0x03

    # Write the changes back to the file
    pe.write(filename)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Set PE header bytes.')
    parser.add_argument('filename', help='The filename of the PE file to modify')
    parser.add_argument('--file', action='store_true', default=True, help='Handle a single file.')
    parser.add_argument('--folder', action='store_true', help='Handle a whole folder (non-recursively).')
    args = parser.parse_args()

    if args.folder:
        if os.path.isdir(args.filename):
            # Handle the folder here.
            print(f"Handling folder: {args.filename}")
            for file_name in os.listdir(args.filename):
                file_path = os.path.join(args.filename, file_name)
                if os.path.isfile(file_path):
                    # Handle the file here.
                    restoreHeader(file_path)
                else:
                    pass
                    #print(f"  - Skipping non-file: {file_path}")
        else:
            print(f"Error: {args.filename} is not a directory.")
    else:
        if os.path.isfile(args.filename):
            # Handle the file here.
            print(f"Handling file: {args.filename}")
        else:
            print(f"Error: {args.filename} is not a file.")
    

if __name__ == '__main__':
    main()