from ast import arg
import os
import glob

samples_folder = "/home/kali/Downloads/Windows"
samples_folder = "/home/kali/Documents/Samples/malware_nocompression"
strings_out_folder = "/home/kali/Downloads/strings_result/"
yara_out_folder = "/home/kali/Documents/yara_result_unp_nc/"

strings_cmd = "strings"

def build_shell_command(command, arguments_list: list()):
    separator = " "
    args = separator.join(arguments_list)
    return command + " " + args

#command = build_shell_command(strings_cmd, ["/home/kali/Downloads/Windows/MSIL_Filecoder.CS.ex > /home/kali/Downloads/analysis.txt"])
#os.system(command)

def iterate_samples(folder, command, arguments_before, arguments_after, outputPath):
    files = glob.glob(folder + "/*")
    non_empty_yara_files = 0
    # check the output directiry
    if not os.path.exists(outputPath):
            os.mkdir(outputPath)

    for filepath in files:
        args = []
        args.extend(arguments_before)
        args.append(filepath)
        args.extend(arguments_after)
        args.append(">")
        basename = os.path.basename(filepath)
        final_filename = basename.replace(".ex", ".txt")
        args.append(os.path.join(outputPath, final_filename))
        cmd = build_shell_command(command, args)
        print("Executing: $", cmd)
        os.system(cmd)

        #check if file is empty
        if os.stat(os.path.join(outputPath, final_filename)).st_size == 0:
            os.remove(os.path.join(outputPath, final_filename))
        else:
            non_empty_yara_files += 1
            
        
    print("Non empty files:", non_empty_yara_files)
        

def checkPackers(dir, outfile):
    files = glob.glob(dir + "/*")
    
    for filepath in files:
        basename = os.path.basename(filepath)
        f = open(outfile, "a")
        f.write(basename + '\n')
        f.close()

        args = []
        args.append("-j")
        args.append(filepath)
        args.append(">>")
        args.append(outfile)
        cmd = build_shell_command("diec", args)
        os.system(cmd)


#iterate_samples(samples_folder, strings_cmd, [], [""], strings_out_folder)

yara_cmd = "yara"
yara_rules_path = "/home/kali/Downloads/crypto_signatures.yara"
yara_args = ["-s", "-r", yara_rules_path]

#iterate_samples(samples_folder, yara_cmd, yara_args, [], yara_out_folder)

out = "/home/kali/Documents/Workspace/subsetNormal-packers-info.json"
checkPackers(samples_folder, out)
