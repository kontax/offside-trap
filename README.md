# Offside Trap
A proof-of-concept ELF obfuscation script which encrypts individually selected functions, and decrypts them on
the fly during runtime.

## Requirements
Offside-trap is written in Python, with the exception of the loader code which is in x86 assembly. The following
software and Python packages are required:
* Python 3
* virtualenv
* pip
* nasm: To build the assembly bytecode
* radare2: Analysis of functions when symbols are not available

And the following Python packages are installed:
* capstone: For instruction analysis (not implemented yet)
* r2pipe: Piping instructions between the r2 analyser and Python
* pyelftools: Not required - used for testing the ELF parser
* requests: Used only within the test suite to upload samples to VirusTotal

## Installation
Create a new virtual environment in the directory, and install the required packages:
~~~~
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
~~~~

## Usage
~~~~
usage: offside_trap.py [-h] [-l] [-e] [-k KEY] [-r] [-f FUNCTION] [-a] BINARY

Encrypt a binary

positional arguments:
  BINARY                The binary to encrypt

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            List the functions available to encrypt
  -e, --encrypt         Encrypt the binary
  -k KEY, --key KEY     The XOR key used to encrypt the binary
  -r, --random          Choose a random key to encrypt with
  -f FUNCTION, --function FUNCTION
                        A function to encrypt (list multiple if required)
  -a, --all             Encrypt all functions
~~~~

## Testing
1. Load in the test binaries into test/{bin,virus}
    1. "bin" contains the binaries to test speed, correctness and size in
    2. "virus" contains malicious binaries to test against VirusTotal
2. Create a VirusTotal API key and store it in src/conf/keys.py, within the variable VIRUS_TOTAL_API_KEY
3. ```python src/test_runner.py```
4. Results will be saved in results.json