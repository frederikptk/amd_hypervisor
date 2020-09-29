#!/bin/bash

cd ..
./build.sh
cd user

echo "################################"
echo "     INSERT KERNEL MODULE"
echo "################################"
sudo insmod ../kernel/hyperkraken.ko

echo "################################"
echo "       RUN USERLAND TEST"
echo "################################"
sudo ../example
sudo rmmod hyperkraken
