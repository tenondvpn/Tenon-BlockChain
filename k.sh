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
13.231.66.82 \
35.180.203.128 \
54.79.153.115 \
3.26.54.18 \
18.197.107.5 \
35.159.15.162 \
3.67.95.8 \
216.108.231.19 \
216.108.227.52 \
216.108.231.102 \
216.108.231.103 \
216.108.231.105 \
18.183.236.105 \
18.181.165.106 \
13.114.123.72 \
3.113.15.65 \
3.112.150.233 \
18.182.13.157 \
18.182.64.146 \
18.183.225.123 \
54.180.1.135 \
13.125.101.235 \
13.125.58.171 \
54.169.190.156 \
13.229.232.107 \
13.250.46.98 \
18.139.2.86 \
18.141.12.113 \
52.77.230.175 \
13.229.232.22 \
13.126.252.68 \
13.232.10.68 \
13.233.94.96 \
18.156.69.139 \
3.12.73.217 \
3.137.186.226 \
3.22.68.200 \
3.138.121.98 \
18.188.190.127 \
15.236.40.28 \
35.180.62.111 \
54.198.157.144 \
35.153.74.125 \
35.183.32.198 \
3.96.184.169 \
13.36.169.102 \
35.180.121.183 \
15.236.37.30 \
52.78.57.83 \
13.124.164.185 \
3.36.113.104 \
13.55.164.90 \
52.90.210.193 \
3.89.136.146 \
54.172.51.176 \
3.88.46.61 \
3.84.68.209 \
54.162.14.164 \
54.162.52.163 \
34.229.209.5 \
3.80.178.150 \
3.81.2.11 \
54.156.45.108 \
35.182.30.220 \
35.183.4.21 \
18.170.73.99 \
18.130.60.55 \
18.130.243.251 \
18.132.41.92 \
18.197.107.5 \
35.159.15.162 \
3.120.175.183 \
3.67.95.8 \
35.156.6.5 \
54.93.213.145 \
)

for ip in ${IP[@]};
do
    echo $ip
    sshpass -p Xf4aGbTaf9 ssh -o "StrictHostKeyChecking no" -o ServerAliveInterval=5  root@$ip "ps -ef | grep tenon | awk -F' ' '{print \$2}' | xargs kill -9" 
done
