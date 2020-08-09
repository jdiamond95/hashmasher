import os
import time
import argparse

from lib.output import printOutput
from lib.helper import *

banner = """
 _               _                         _               
| |__   __ _ ___| |__  _ __ ___   __ _ ___| |__   ___ _ __ 
| '_ \ / _` / __| '_ \| '_ ` _ \ / _` / __| '_ \ / _ \ '__|
| | | | (_| \__ \ | | | | | | | | (_| \__ \ | | |  __/ |   
|_| |_|\__,_|___/_| |_|_| |_| |_|\__,_|___/_| |_|\___|_|   
														   
"""



def main():
	if args.file:
		# Print output should take a hash and call the VT lookup etc
		print(args.file)
		printOutput(args.file, getFileName(args.file), "File")

	elif args.directory:
		if args.recursive:
			files = getFileList(args.directory, True)
		else:
			files = getFileList(args.directory, False)
		print(files)
		for i in range(0, len(files)):
			printOutput(files[i], getFileName(files[i]), i)
			time.sleep(15)


if __name__ == "__main__":
	print(banner)	
	parser = argparse.ArgumentParser(description="Bulk Hash Lookup Tool")
	parser.add_argument('-f', "--file", help="Select a file to lookup", type=str)
	parser.add_argument('-d', "--directory", help="Absolute or relative directory path of files to be hashed", type=str)
	parser.add_argument('-r', "--recursive", help="Search recursively", action='store_const', const='recursive')	
	args = parser.parse_args()
	main()
