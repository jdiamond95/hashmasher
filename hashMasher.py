import os
import time
import argparse

vtAPIKey = os.environ.get('VTAPIKey')
virusTotalBase = "https://www.virustotal.com/vtapi/v2/"
vtFileReport = "file/report"
session = requests.Session()
fileBlockSize = 65536
banner = """
 _               _                         _               
| |__   __ _ ___| |__  _ __ ___   __ _ ___| |__   ___ _ __ 
| '_ \ / _` / __| '_ \| '_ ` _ \ / _` / __| '_ \ / _ \ '__|
| | | | (_| \__ \ | | | | | | | | (_| \__ \ | | |  __/ |   
|_| |_|\__,_|___/_| |_|_| |_| |_|\__,_|___/_| |_|\___|_|   
														   
"""



def main():
	if args.file:
		printOutput(queryVirusTotal(getFileHash(args.file)), args.file, 'File')

	elif args.directory:
		hashes, files = getHashList(args.directory)
		for i in range(0, len(hashes)):
			printOutput(queryVirusTotal(hashes[i]), files[i], i + 1)
			time.sleep(15)


if __name__ == "__main__":
	print(banner)
	parser = argparse.ArgumentParser(description="Bulk Hash Lookup Tool")
	parser.add_argument('-d', "--directory", help="Absolute or relative directory path of files to be hashed", type=str)
	parser.add_argument('-r', "--recursive", help="Search recursively", type=str)
	parser.add_argument('-f', "--file", help="Select a file to lookup", type=str)
	args = parser.parse_args()
	main()
