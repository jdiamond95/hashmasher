
# hashmasher

HashMasher is a command line based hash lookup tool. It's useful in incident response instances where a large number of file hashes need to quickly looked up for quick wins.

## Usage

<!-- language: lang-none -->
	 _               _                         _               
	| |__   __ _ ___| |__  _ __ ___   __ _ ___| |__   ___ _ __ 
	| '_ \ / _` / __| '_ \| '_ ` _ \ / _` / __| '_ \ / _ \ '__|
	| | | | (_| \__ \ | | | | | | | | (_| \__ \ | | |  __/ |   
	|_| |_|\__,_|___/_| |_|_| |_| |_|\__,_|___/_| |_|\___|_|   

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

## Setup
###  Virtual Env and Dependancies
Initialise a Python Virtual Environment ([https://virtualenv.pypa.io/en/latest/](https://virtualenv.pypa.io/en/latest/)) using: `virtualenv venv`. Activate the virtual environment using `source venv/bin/activate` then install all dependencies using `pip install -r requirements.txt`.

### Environment Variables
The script relies on environment variables to access API keys so they're not straight in the code. Add the following variables in your .bash_profile

VTAPIKEY='12345678901234567890'