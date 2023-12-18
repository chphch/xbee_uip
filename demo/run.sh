IP="192.168.0.101"
make
scp ./dtls_server "root@$IP:/home/root"
ssh "root@$IP" /home/root/dtls_server /dev/ttySTM3
