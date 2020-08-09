import os

def getFileName(file):
	return file.split("/").pop()


def getFileList(path, recursive):
	hashes = []
	files = []
	#Recurse through all files in the directory
	if recursive:
		for dirpath, dirnames, files in os.walk(path):
			for file in files:
				files.append(path + file)
	#Not recursive - just go through files in that directory
	else:
		for file in os.listdir(path):
			if os.path.isfile(os.path.join(path,file)):
				files.append(path + file)
	return files