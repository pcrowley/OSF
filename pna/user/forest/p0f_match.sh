#!/bin/bash

cp data_1000.txt rf_data.txt
cp data_real.txt rf_data_test.txt
cp truth_1000.txt rf_truth.txt
cp truth_real.txt rf_truth_test.txt
R CMD BATCH ~/pna/user/forest/forest_p0f_match.R
./match r_real.out rf_truth_test.txt
