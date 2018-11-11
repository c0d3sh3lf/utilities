#!/usr/bin/python

### Calculates hash SHA256 of all files present inside a parent folder and its subfolders.

import hashlib, os, sys

def hash256file(file_obj):
    file_data = file_obj.read()

    sha256_hash = str(hashlib.sha256(file_data).hexdigest())
    return sha256_hash


def readallfiles(folder_path):
    root_dir = folder_path

    hashes = {}

    for root, subFolders, files in os.walk(root_dir):
        for filename in files:
                filePath = os.path.join(root, filename)
                f = open(filePath, 'r')
                print "[+] Calculating hash for", filePath, 
                hash_f = str(hash256file(f))
                print "-", hash_f
                hashes[filePath] = hash_f
                f.close()
    return hashes

def writetofile(hashes, folder_path):
    output_file_name = os.path.join(folder_path, "hashes.csv")
    folderOut = open(output_file_name, "w")
    for filename in hashes.keys():
        folderOut.write(filename + "," + hashes[filename] + "\n")
    print "[+] Output filename is", output_file_name
    folderOut.close()

def main():
    folder_path = sys.argv[1]
    writetofile(readallfiles(folder_path), folder_path)

if __name__ == "__main__":
    main()
