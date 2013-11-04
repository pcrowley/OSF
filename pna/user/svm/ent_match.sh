#!/bin/bash

cp data_ent_4000.txt svm_data.txt
cp data_ent_test.txt svm_data_test.txt
cp truth_ent_4000.txt svm_truth.txt
cp truth_ent_test.txt svm_truth_test.txt
python svm.py
