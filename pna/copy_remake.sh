make stop
make clean
make
cd user
./copy_remake.sh
cd ..
make start
sudo service/pna load pna_bulkcopy
