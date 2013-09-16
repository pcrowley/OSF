#!/bin/bash
gcc -O3 -lgomp ml_osc.c hash_32a.c murmur3.c pna_hashmap.c ~/libsvm/libsvm.so.2 -o ml_osc

