rm -rf /root/nodes/*/tenon /root/nodes/*/core* /root/nodes/*/log/* /root/nodes/*/*db 
sh build.sh
IP=(\
216.108.228.54 \
216.108.228.8 \
64.235.33.103 \
216.108.228.109 \
64.235.33.90 \
64.235.33.93 \
64.235.37.100 \
64.235.37.53 \
64.235.37.66 \
)

for ip in ${IP[@]};
do
    echo $ip
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "ps -ef | grep tenon_s | awk -F' ' '{print \$2}' | xargs kill -9" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "ps -ef | grep tenon1 | awk -F' ' '{print \$2}' | xargs kill -9" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "ps -ef | grep tenon2 | awk -F' ' '{print \$2}' | xargs kill -9" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "ps -ef | grep tenon3 | awk -F' ' '{print \$2}' | xargs kill -9" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "ps -ef | grep tenon4 | awk -F' ' '{print \$2}' | xargs kill -9" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "rm -rf /root/tenon/tenon_s /root/tenon/core* /root/tenon/log/* /root/tenon/*db" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "rm -rf /root/n1/tenon1 /root/n1/core* /root/n1/log/* /root/n1/*db" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "rm -rf /root/n2/tenon2 /root/n2/core* /root/n2/log/* /root/n2/*db" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "rm -rf /root/n3/tenon3 /root/n3/core* /root/n3/log/* /root/n3/*db" 
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "rm -rf /root/n4/tenon4 /root/n4/core* /root/n4/log/* /root/n4/*db" 
    sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild_Release/tenon root@$ip:/root/tenon/tenon_s
    sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild_Release/tenon root@$ip:/root/n1/tenon1
    sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild_Release/tenon root@$ip:/root/n2/tenon2
    sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild_Release/tenon root@$ip:/root/n3/tenon3
    sshpass -p Xf4aGbTaf9 scp -o "StrictHostKeyChecking no" ./cbuild_Release/tenon root@$ip:/root/n4/tenon4
done

cp -rf ./cbuild_Release/tenon /root/nodes/tenon
cd /root/nodes/tenon && ./tenon -U -1 031d29587f946b7e57533725856e3b2fc840ac8395311fea149642334629cd5757:127.0.0.1:1,03a6f3b7a4a3b546d515bfa643fc4153b86464543a13ab5dd05ce6f095efb98d87:127.0.0.1:2,031e886027cdf3e7c58b9e47e8aac3fe67c393a155d79a96a0572dd2163b4186f0:127.0.0.1:2 -2 0315a968643f2ada9fd24f0ca92ae5e57d05226cfe7c58d959e510b27628c1cac0:127.0.0.1:3,030d62d31adf3ccbc6283727e2f4493a9228ef80f113504518c7cae46931115138:127.0.0.1:4,028aa5aec8f1cbcd995ffb0105b9c59fd76f29eaffe55521aad4f7a54e78f01e58:127.0.0.1:5
cd /root/nodes/tenon && ./tenon -S

RIP=(\
216.108.228.54 \
216.108.228.8 \
64.235.33.103 \
)

for ip in ${RIP[@]};
do
    echo $ip
    sshpass -p Xf4aGbTaf9 scp -r -o "StrictHostKeyChecking no" /root/nodes/tenon/root_db root@$ip:/root/tenon/db
done

SIP=(\
64.235.33.90 \
64.235.33.93 \
64.235.37.100 \
)

for ip in ${SIP[@]};
do
    echo $ip
    sshpass -p Xf4aGbTaf9 scp -r -o "StrictHostKeyChecking no" /root/nodes/tenon/shard_db root@$ip:/root/tenon/db
done


sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@216.108.228.54 "cd /root/tenon && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/install/lib64/ nohup ./tenon_s -f 1 -g 0" & 
sleep 5

IP=(\
216.108.228.8 \
64.235.33.103 \
64.235.33.90 \
64.235.33.93 \
64.235.37.100 \
)

for ip in ${IP[@]};
do
    echo $ip
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root/tenon && ulimit -c unlimited && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/install/lib64/ nohup ./tenon_s -f 0 -g 0" & 
done

IP=(\
216.108.228.54
216.108.228.8 \
64.235.33.103 \
216.108.228.109 \
64.235.33.90 \
64.235.33.93 \
64.235.37.100 \
64.235.37.53 \
64.235.37.66 \
)

for ip in ${IP[@]};
do
    echo $ip
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root/n1 && ulimit -c unlimited && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/install/lib64/ nohup ./tenon1 -f 0 -g 0" &
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root/n2 && ulimit -c unlimited && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/install/lib64/ nohup ./tenon2 -f 0 -g 0" &
    #sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root/n3 && ulimit -c unlimited && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/install/lib64/ nohup ./tenon3 -f 0 -g 0" &
    #sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "cd /root/n4 && ulimit -c unlimited && LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/install/lib64/ nohup ./tenon4 -f 0 -g 0" &
done

