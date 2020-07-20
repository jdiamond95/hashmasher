import os
import time
import argparse
import requests
import fabulous
import hashlib
from colorama import Fore, Back, Style

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

def printOutput(vtOutput, name, number):
	if vtOutput['response_code'] == 1:
		detectionPercentage = vtOutput['positives']/vtOutput['total']

	if vtOutput['response_code'] == 0:
		print(Back.WHITE + Fore.BLACK)
		print(str(number) + ": " + name + Style.RESET_ALL)
		print("Resource: " + vtOutput['resource'])
		print("No VirusTotal results found")
		return

	if detectionPercentage == 0:
		print(Back.GREEN)
	elif detectionPercentage < 0.1:
		print('\033[43m')
	else:
		print(Back.RED)
	print(str(number) + ": " + name + " - " + str(vtOutput['positives']) + "/" + str(vtOutput['total']) + Style.RESET_ALL)
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
	files = []
	#Recurse through all files in the directory
	if args.recursive:
		for dirpath, dirnames, files in os.walk(path):
			for file in files:
				hashes.append(getFileHash(file))
				files.append(file)
	#Not recursive - just go through files in that directory
	else:
		for file in os.listdir(path):
			if os.path.isfile(os.path.join(path,file)):
				hashes.append(getFileHash(os.path.join(path,file)))
				files.append(file)
	return hashes, files


def getFileHash(file):
	newHash = hashlib.sha256()
	with open(file, 'rb') as f:
		fileBlock = f.read(fileBlockSize)
		while len(fileBlock) > 0:
			newHash.update(fileBlock)
			fileBlock = f.read(fileBlockSize)
	return newHash.hexdigest()


def main():
	if args.file:
		printOutput(queryVirusTotal(getFileHash(args.file)), args.file, 'File')

	elif args.directory:
		hashes, files = getHashList(args.directory)
		for i in range(0, len(hashes)):
			printOutput(queryVirusTotal(hashes[i]), files[i], i + 1)
			# time.sleep(26)

if __name__ == "__main__":
	print(banner)
	parser = argparse.ArgumentParser(description="Bulk Hash Lookup Tool")
	parser.add_argument('-d', "--directory", help="Absolute or relative directory path of files to be hashed", type=str)
	parser.add_argument('-r', "--recursive", help="Search recursively", type=str)
	parser.add_argument('-f', "--file", help="Select a file to lookup", type=str)
	args = parser.parse_args()
	main()
