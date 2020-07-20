import os
import argparse
import requests
import fabulous
import hashlib

#Mimikatz - fb55414848281f804858ce188c3dc659d129e283bd62d58d34f6e6f568feab37
vtAPIKey = os.environ.get('VTAPIKey')

virusTotalBase = "https://www.virustotal.com/vtapi/v2/"
vtFileReport = "file/report"
session = requests.Session()
fileBlockSize = 65536


def printOutput(vtOutput):
    print("MD5: " + vtOutput['md5'])
    print("SHA1: " + vtOutput['sha1'])
    print("SHA256: " + vtOutput['sha256'] + "\n")
    print("VirusTotal Link: " + vtOutput['permalink'])


def queryVirusTotal(hash):
    params = {
    'apikey': vtAPIKey,
    'resource': hash
    }
    url = virusTotalBase + vtFileReport 
    try:
        r = session.get(virusTotalBase + vtFileReport, params=params)
        return r.json()

    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
        return 0


def getHashList(path):
    hashes = []

    #Recurse through all files in the directory
    if args.recursive:
        for dirpath, dirnames, files in os.walk(path):
            for file in files:
                hashes.append(getFileHash(file))

    #Not recursive - just go through files in that directory
    else:
        for file in os.listdir(path):
            if os.path.isfile(os.path.join(path,file)):
                hashes.append(getFileHash(os.path.join(path,file)))
    print(hashes)
    return hashes


def getFileHash(file):
    newHash = hashlib.sha256()
    with open(file, 'rb') as f:
        fileBlock = f.read(fileBlockSize)
        while len(fileBlock) > 0:
            newHash.update(fileBlock)
            fileBlock = f.read(fileBlockSize)
    print(file + ": " + newHash.hexdigest())
    return newHash.hexdigest()


def main():
    if args.lookup:
        printOutput(queryVirusTotal(args.lookup))

    elif args.directory:
        getHashList(args.directory)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk Hash Lookup Tool")
    parser.add_argument('-l', "--lookup", help="Single MD5, SHA1, SHA256 to lookup", type=str)
    parser.add_argument('-d', "--directory", help="Absolute or relative directory path of files to be hashed", type=str)
    parser.add_argument('-r', "--recursive", help="Search recursively", type=str)
    args = parser.parse_args()
    main()
