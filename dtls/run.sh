IP="192.168.0.101"
make
ssh "root@$IP" pkill -9 dtls_server
scp ./dtls_server "root@$IP:/home/root"
ssh "root@$IP" /home/root/dtls_server /dev/ttySTM3
