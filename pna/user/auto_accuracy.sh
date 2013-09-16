#!/bin/bash
rm accuracy.out
cd forest
echo "Forest p0f match:" >> ~/pna/user/accuracy.out
./p0f_match.sh >> ~/pna/user/accuracy.out
echo "Forest synth match:" >> ~/pna/user/accuracy.out
./synth_match.sh >> ~/pna/user/accuracy.out
cd ../svm
echo "SVM p0f match:" >> ~/pna/user/accuracy.out
./p0f_match.sh >> ~/pna/user/accuracy.out
echo "SVM synth match:" >> ~/pna/user/accuracy.out
./synth_match.sh >> ~/pna/user/accuracy.out
cd ..

