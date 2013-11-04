#!/bin/bash

train_pcap=$1
test_pcap=$2

echo "Remaking programs"
./remake_ml_osc.sh

echo "Turning $train_pcap into csv"
./pcap_to_csv $train_pcap > "svm_data.txt"
echo "Turning $test_pcap into csv"
./pcap_to_csv $test_pcap > "svm_data_test.txt"

echo "Generating labels for $train_pcap"
p0f/p0f -m 1,1 -f p0f/p0f.fp -r $train_pcap > "p0f.out"
grep "| os\|NMap\|p0f sendsyn" p0f.out > "p0f.txt"
./forwardconvert back.txt p0f.txt > "svm_truth.txt"
mv svm_data.txt svm_temp.txt
./delete_unkn svm_temp.txt svm_truth.txt > svm_data.txt
mv svm_truth.txt svm_temp.txt
./delete_unkn_label svm_temp.txt > svm_truth.txt

echo "Generating labels for $test_pcap"
p0f/p0f -m 1,1 -f p0f/p0f.fp -r $test_pcap > "p0f.out"
grep "| os\|NMap\|p0f sendsyn" p0f.out > "p0f.txt"
./forwardconvert back.txt p0f.txt > "svm_truth_test.txt"

echo "Generating svm.model, this could take a while"
python svm.py
rm svm_data.txt
rm svm_data_test.txt
rm svm_truth.txt
rm svm_truth_test.txt
rm p0f.out
rm p0f.txt
