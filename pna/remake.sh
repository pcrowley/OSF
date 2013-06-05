make stop
make clean
make
cd user
./osf_remake.sh
cd ..
make start
sudo service/pna load pna_osfmon
