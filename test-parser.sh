#!/bin/bash
set -e

function run_test() {
    python elf_parser.py > /dev/null
    cp test/packed ./test-bin
    \ls -s ./test-bin
    chmod +x ./test-bin
    ./test-bin > /dev/null
}

echo "Dynamic + PIE"
gcc -o test/test test/test.c                  # Dynamic + PIE
run_test

echo "Dynamic + No-PIE"
gcc -no-pie -o test/test test/test.c          # Dynamic + No-PIE
run_test

echo "Static + No-PIE"
gcc -no-pie -static -o test/test test/test.c  # Static + No-PIE
run_test

rm test-bin
