#!/bin/bash 

count=0

while [ $count -lt 1000 ]
do
	cat $1 >> $2
	count=$((count + 1))
done
