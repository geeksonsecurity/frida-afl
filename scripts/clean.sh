#!/bin/bash

m=`ipcs -m | cut -d' ' -f2`
echo $m
for i in $m
do
        echo removing shm id $i
        ipcrm -m $i
done
