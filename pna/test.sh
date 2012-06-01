rm raw_log.osf hr_out.osf
echo "Starting PNA..."
make start
echo "PNA loaded"
echo "Initializing PNA"
sudo ./osf_control -l 1000 -d 500
echo "Loading Database"
sudo ./db_load tcp.osf
echo "Done"
