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
clang -Wall -I../include testcases/infinite_loop.c -o output/infinite_loop
clang -Wall -I../include testcases/multiple_guests.c -o output/multiple_guests

echo "################################"
echo "         RUNNING TESTS"
echo "################################"
cd output
#echo "[TEST]: COW"
#sudo ./cow > cow.output
#diff cow.output ../testcases/cow.output
#if (( $? != 0 )); then
#    echo "[TEST FAILED]"
#else
#    echo "[TEST PASSED]"
#fi


#echo "[TEST]: INFINITE LOOP"
#sudo ./infinite_loop
#echo "[TEST PASSED]"


echo "[TEST]: MULTIPLE GUESTS"
sudo ./multiple_guests > multiple_guests.output
diff multiple_guests.output ../testcases/multiple_guests.output
if (( $? != 0 )); then
    echo "[TEST FAILED]"
else
    echo "[TEST PASSED]"
fi




# Cleanup
sudo rmmod hyperkraken