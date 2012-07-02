echo "Rebuilding userspace programs"
cd bin
rm control_read db_load log_read osf_control p0f_convert convert_log calculate_capacity
cd ../src
gcc -w control_read.c -o ../bin/control_read
gcc -w db_load.c -o ../bin/db_load
gcc -w log_read.c -o ../bin/log_read
gcc -w osf_control.c -o ../bin/osf_control
gcc -w p0f_convert.c -o ../bin/p0f_convert
gcc -w convert_log.c -o ../bin/convert_log
gcc -w calculate_capacity.c -o ../bin/calculate_capacity
gcc -w autolog.c -o ../bin/autolog
cd ../..
echo "Rebuilding kernel module"
cd module
rm *.o *.ko
cd ..
make
echo "Done"
