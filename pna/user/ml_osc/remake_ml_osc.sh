#!/bin/bash
gcc -w forwardconvert.c -o forwardconvert
gcc -w pcap_to_csv.c hash_32a.c -lpcap -o pcap_to_csv
gcc -w delete_unkn.c -o delete_unkn
gcc -w delete_unkn_label.c -o delete_unkn_label
gcc ml_osc.c hash_32a.c pna_hashmap.c murmur3.c -w -lpcap -lsvm -o ml_osc
cd p0f
./build.sh
