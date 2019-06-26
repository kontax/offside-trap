#!/bin/bash
set -e

echo "Dynamic + PIE"
gcc -o test/test test/test.c                  # Dynamic + PIE
python elf_parser.py > /dev/null
cp test/packed ./test-bin
\ls -s ./test-bin
./test-bin > /dev/null

echo "Dynamic + No-PIE"
gcc -no-pie -o test/test test/test.c          # Dynamic + No-PIE
python elf_parser.py > /dev/null
cp test/packed ./test-bin
\ls -s ./test-bin
./test-bin > /dev/null

echo "Static + No-PIE"
gcc -no-pie -static -o test/test test/test.c  # Static + No-PIE
python elf_parser.py > /dev/null
cp test/packed ./test-bin
\ls -s ./test-bin
./test-bin > /dev/null

rm test-bin
