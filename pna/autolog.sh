rm raw_log.osf hr_out.osf
make start
sudo ./osf_control -l 10000 -d 500
sudo ./db_load tcp.osf
while :
do
	sleep 10
	sudo ./auto_log $(date +osflogs/%s.log)
done
