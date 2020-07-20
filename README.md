 _               _                         _               
| |__   __ _ ___| |__  _ __ ___   __ _ ___| |__   ___ _ __ 
| '_ \ / _` / __| '_ \| '_ ` _ \ / _` / __| '_ \ / _ \ '__|
| | | | (_| \__ \ | | | | | | | | (_| \__ \ | | |  __/ |   
|_| |_|\__,_|___/_| |_|_| |_| |_|\__,_|___/_| |_|\___|_|   
													   

# hashmasher

HashMasher is a command line based hash lookup tool. It's useful in incident response instances where a large number of file hashes need to quickly looked up for quick wins.

# Usage

usage: hashMasher.py [-h] [-d DIRECTORY] [-r RECURSIVE] [-f FILE]

Bulk Hash Lookup Tool

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Absolute or relative directory path of files to be
                        hashed
  -r RECURSIVE, --recursive RECURSIVE
                        Search recursively
  -f FILE, --file FILE  Select a file to lookup

