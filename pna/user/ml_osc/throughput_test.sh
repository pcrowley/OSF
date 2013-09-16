#!/bin/bash
sudo ./ml_osc svm.model &
sleep 5
sudo kill -2 $!
sudo ./ml_osc svm.model &
sleep 10
sudo kill -2 $!
