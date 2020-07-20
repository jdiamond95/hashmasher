# hashmasher

HashMasher is a command line based hash lookup tool. It's useful in incident response instances where a large number of file hashes need to quickly looked up for quick wins.

# Usage
usage: hashMasher.py [-h] [-l LOOKUP] [-d DIRECTORY] [-r RECURSIVE]

Bulk Hash Lookup Tool

optional arguments:
  -h, --help            show this help message and exit
  -l LOOKUP, --lookup LOOKUP
                        Single MD5, SHA1, SHA256 to lookup
  -d DIRECTORY, --directory DIRECTORY
                        Absolute or relative directory path of files to be
                        hashed
  -r RECURSIVE, --recursive RECURSIVE
                        Search recursively