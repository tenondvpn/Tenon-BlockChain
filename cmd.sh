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
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip $1 
done

