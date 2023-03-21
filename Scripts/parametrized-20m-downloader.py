import os

download_folder = "/home/kali/Documents/Samples/malware/"
files = []
filecount = 0
# clear console
clear = lambda: os.system('clear')

with open('samples.txt') as sha_list:
    for line in sha_list:
        files.append(line.strip())

for file in files:
#print(files[0])
    os.system("aws s3 cp s3://sorel-20m/09-DEC-2020/binaries/" + file + " " + download_folder + " --no-sign-request")
    filecount += 1
    print("Files requested:", filecount)
