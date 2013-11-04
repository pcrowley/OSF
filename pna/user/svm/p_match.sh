#!/bin/bash

cp data_1000.txt svm_data.txt
cp data_1000.2.txt svm_data_test.txt
cp truth_1000.txt svm_truth.txt
cp truth_1000.2.txt svm_truth_test.txt

count=0

while [ $count -lt "61" ]
do
	python perturber.py ranges data_1000.2.txt $count > svm_data_test.txt
	python svm.py
	count=$((count+1))
done
