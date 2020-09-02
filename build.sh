#!/bin/bash

echo "################################"
echo "      BUILD KERNEL MODULE"
echo "################################"
cd kernel && make && cd ..
rm kernel/src/*.o
rm kernel/*.o
rm kernel/*.mod
rm kernel/*.symvers
rm kernel/*.mod.c
rm kernel/*.order
echo "DONE"

echo "################################"
echo "      BUILD USERLAND TEST"
echo "################################"
clang -Wall -I./include -I./user/include user/src/main.c -o example
echo "DONE"
