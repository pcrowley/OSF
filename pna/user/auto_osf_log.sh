#!/bin/sh
if [ $# -ne 6 ]
then
	echo "Check usage"
	exit
fi
location=$1
database=$2
num_ips=$3
num_logs=$4
num_db_entries=$5
wait_time=$6

log_entry=0

sudo ./osf_user -c $num_ips $num_logs $num_db_entries
sudo ./osf_user -d $database
echo "0" > auto_log_stop
log_stop=$(cat auto_log_stop)
while [ $log_stop -eq 0 ]
do
	sleep $wait_time
	sudo ./osf_user -r $location/raw$log_entry.log $database $num_ips
	log_stop=$(cat auto_log_stop)
	log_entry=$(($log_entry + 1))
done
