#!/bin/sh
rm perf.res
sudo ./auto_osf_log.sh osf_logs osf.fp 500000 10 500 10 &
count=0
while (($count < 2))
do
	./perf_read >> perf.res
	rm -f osf_logs/*.log
	rm -f ../logs/*
	sleep 20
	rm -f osf_logs/*.log
	rm -f ../logs/*
	sleep 20
	rm -f osf_logs/*.log
	rm -f ../logs/*
	sleep 20
done
echo "1" > auto_log_stop
sleep 15
cd ..
make stop
