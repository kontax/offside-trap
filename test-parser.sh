#!/bin/bash
set -e

function run_test() {
    #python poc.py > /dev/null
    python offside_trap.py -er -f sym.add -f sym.mul -f sym.sub -f main test/test > /dev/null
    cp test/test.packed ./test-bin
    \ls -s ./test-bin
    chmod +x ./test-bin
    PRE=$(./test/test)
    POST=$(./test-bin)
    if [ "$PRE" == "$POST" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
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
