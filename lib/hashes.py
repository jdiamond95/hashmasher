import hashlib

fileBlockSize = 65536


def getFileHash(file):
	newHash = hashlib.sha256()
	with open(file, 'rb') as f:
		fileBlock = f.read(fileBlockSize)
		while len(fileBlock) > 0:
			newHash.update(fileBlock)
			fileBlock = f.read(fileBlockSize)
	return newHash.hexdigest()