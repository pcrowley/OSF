#!/bin/bash

cp data_1000.txt svm_data.txt
cp data_real.txt svm_data_test.txt
cp truth_1000.txt svm_truth.txt
cp truth_real.txt svm_truth_test.txt
python svm.py