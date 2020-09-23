#!/bin/bash

echo "################################"
echo "      BUILD KERNEL MODULE"
echo "################################"
cd kernel && make && cd ..

find . -name \*.o -type f -delete
find . -name \*.o.d -type f -delete
find . -name \*.cmd -type f -delete
find . -name \*.mod -type f -delete
find . -name \*.symvers -type f -delete
find . -name \*.mod.c -type f -delete
find . -name \*.order -type f -delete

echo "DONE"

echo "################################"
echo "      BUILD USERLAND TEST"
echo "################################"
clang -Wall -I./include -I./user/include user/src/main.c -o example
echo "DONE"
