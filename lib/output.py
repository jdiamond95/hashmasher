import fabulous
from colorama import Fore, Back, Style

from lib.virusTotal import queryVirusTotal
from lib.hashes import getFileHash

def printVT(vtOutput, name, number):
	if vtOutput['response_code'] == 1:
		detectionPercentage = vtOutput['positives']/vtOutput['total']

	if vtOutput['response_code'] == 0:
		print(Back.WHITE + Fore.BLACK)
		print(str(number) + ": " + name + Style.RESET_ALL)
		print("Resource: " + vtOutput['resource'])
		print("No VirusTotal results found")
		print(vtOutput)
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



def printOutput(file, name, number):
	#Call all the specific resource outputting functions here
	printVT(queryVirusTotal(getFileHash(file)), name, number)
