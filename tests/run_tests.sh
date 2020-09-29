#!/bin/bash

rm -rf output
mkdir output

cd ..
./build.sh
cd tests

echo "################################"
echo "     INSERT KERNEL MODULE"
echo "################################"
sudo insmod ../kernel/hyperkraken.ko

echo "################################"
echo "         BUILDING TESTS"
echo "################################"
clang -Wall -I../include testcases/cow.c -o output/cow

echo "################################"
echo "         RUNNING TESTS"
echo "################################"
cd output
sudo ./cow > cow.output
diff cow.output ../testcases/cow.output
if (( $? != 0 )); then
    echo "[TEST FAILED]"
else
    echo "[TEST PASSED]"
fi

# Cleanup
sudo rmmod hyperkraken