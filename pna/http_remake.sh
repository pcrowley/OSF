make stop
make clean
make
cd user
./http_remake.sh
cd ..
make start
sudo service/pna load pna_httpmon
