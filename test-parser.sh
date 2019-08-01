#!/bin/bash
set -e

function run_test() {
    #python poc.py > /dev/null
    python src/offside_trap.py -er -f add -f mul -f sub -f main test/source/test > /dev/null
    cp test/source/test.packed ./test-bin
    \ls -s ./test-bin
    chmod +x ./test-bin
    PRE=$(./test/source/test)
    POST=$(./test-bin)
    if [ "$PRE" == "$POST" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

echo "Dynamic + PIE"
gcc -o test/source/test test/source/test.c                  # Dynamic + PIE
run_test

echo "Dynamic + No-PIE"
gcc -no-pie -o test/source/test test/source/test.c          # Dynamic + No-PIE
run_test

echo "Static + No-PIE"
gcc -no-pie -static -o test/source/test test/source/test.c  # Static + No-PIE
run_test

rm test-bin
