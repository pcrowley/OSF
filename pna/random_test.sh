sudo ./log_read
sudo ./convert_log
diff hr_out.osf random_test.chk
echo "Done"
sudo rmmod pna
