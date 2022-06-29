#!/bin/bash

ps -ef | grep tenon | awk -F' ' '{print $2}' | xargs kill -9
sh build.sh

rm -rf /root/nodes/*/tenon /root/nodes/*/core* /root/nodes/*/log/* /root/nodes/*/*db
mkdir -p /root/nodes/tenon/log
mkdir -p /root/nodes/s1/log
mkdir -p /root/nodes/s2/log
mkdir -p /root/nodes/s3/log
mkdir -p /root/nodes/s4/log
mkdir -p /root/nodes/s5/log
mkdir -p /root/nodes/s6/log
mkdir -p /root/nodes/s7/log
mkdir -p /root/nodes/s8/log
mkdir -p /root/nodes/s9/log
mkdir -p /root/nodes/s10/log
mkdir -p /root/nodes/s11/log
mkdir -p /root/nodes/s12/log
mkdir -p /root/nodes/s13/log
mkdir -p /root/nodes/s14/log
mkdir -p /root/nodes/s15/log
mkdir -p /root/nodes/s16/log
mkdir -p /root/nodes/s17/log
mkdir -p /root/nodes/s18/log
mkdir -p /root/nodes/r1/log
mkdir -p /root/nodes/r2/log
mkdir -p /root/nodes/r3/log
mkdir -p /root/nodes/r4/log
mkdir -p /root/nodes/r5/log
mkdir -p /root/nodes/r6/log
mkdir -p /root/nodes/r7/log

cp -rf ./cbuild_Debug/tenon /root/nodes/tenon
cp -rf ./cbuild_Debug/tenon /root/nodes/s1
cp -rf ./cbuild_Debug/tenon /root/nodes/s2
cp -rf ./cbuild_Debug/tenon /root/nodes/s3
cp -rf ./cbuild_Debug/tenon /root/nodes/s4
cp -rf ./cbuild_Debug/tenon /root/nodes/s5
cp -rf ./cbuild_Debug/tenon /root/nodes/s6
cp -rf ./cbuild_Debug/tenon /root/nodes/s7
cp -rf ./cbuild_Debug/tenon /root/nodes/s8
cp -rf ./cbuild_Debug/tenon /root/nodes/s9
cp -rf ./cbuild_Debug/tenon /root/nodes/s10
cp -rf ./cbuild_Debug/tenon /root/nodes/s11
cp -rf ./cbuild_Debug/tenon /root/nodes/s12
cp -rf ./cbuild_Debug/tenon /root/nodes/s13
cp -rf ./cbuild_Debug/tenon /root/nodes/s14
cp -rf ./cbuild_Debug/tenon /root/nodes/s15
cp -rf ./cbuild_Debug/tenon /root/nodes/s16
cp -rf ./cbuild_Debug/tenon /root/nodes/s17
cp -rf ./cbuild_Debug/tenon /root/nodes/s18
cp -rf ./cbuild_Debug/tenon /root/nodes/r1
cp -rf ./cbuild_Debug/tenon /root/nodes/r2
cp -rf ./cbuild_Debug/tenon /root/nodes/r3
cp -rf ./cbuild_Debug/tenon /root/nodes/r4
cp -rf ./cbuild_Debug/tenon /root/nodes/r5
cp -rf ./cbuild_Debug/tenon /root/nodes/r6
cp -rf ./cbuild_Debug/tenon /root/nodes/r7

cd /root/nodes/tenon && ./tenon -U -1 031d29587f946b7e57533725856e3b2fc840ac8395311fea149642334629cd5757:127.0.0.1:1,03a6f3b7a4a3b546d515bfa643fc4153b86464543a13ab5dd05ce6f095efb98d87:127.0.0.1:2,031e886027cdf3e7c58b9e47e8aac3fe67c393a155d79a96a0572dd2163b4186f0:127.0.0.1:2 -2 0315a968643f2ada9fd24f0ca92ae5e57d05226cfe7c58d959e510b27628c1cac0:127.0.0.1:3,030d62d31adf3ccbc6283727e2f4493a9228ef80f113504518c7cae46931115138:127.0.0.1:4,028aa5aec8f1cbcd995ffb0105b9c59fd76f29eaffe55521aad4f7a54e78f01e58:127.0.0.1:5
cd /root/nodes/tenon && ./tenon -S

cp -rf /root/nodes/tenon/root_db /root/nodes/r1/db
cp -rf /root/nodes/tenon/root_db /root/nodes/r2/db
cp -rf /root/nodes/tenon/root_db /root/nodes/r3/db
cp -rf /root/nodes/tenon/root_db /root/nodes/r4/db
cp -rf /root/nodes/tenon/root_db /root/nodes/r5/db
cp -rf /root/nodes/tenon/root_db /root/nodes/r6/db
cp -rf /root/nodes/tenon/root_db /root/nodes/r7/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s1/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s2/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s3/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s4/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s5/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s6/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s7/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s8/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s9/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s10/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s11/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s12/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s13/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s14/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s15/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s16/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s17/db
cp -rf /root/nodes/tenon/shard_db /root/nodes/s18/db

cd /root/nodes/r1/ && nohup ./tenon -f 1 -g 0 &
sleep 3

cd /root/nodes/r2/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/r3/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/r4/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/r5/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/r6/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/r7/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s1/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s2/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s3/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s4/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s5/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s6/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s7/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s8/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s9/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s10/ && nohup ./tenon -f 0 -g 0 &

clickhouse-client -q "drop table tenon_ck_account_key_value_table"
clickhouse-client -q "drop table tenon_ck_account_table"
clickhouse-client -q "drop table tenon_ck_block_table"
clickhouse-client -q "drop table tenon_ck_statistic_table"
clickhouse-client -q "drop table tenon_ck_transaction_table"
cd /root/n2 &&  rm -rf db ./log/* && nohup ./tenon2 -f 0 -g 0 &
cd /root/n3 &&  rm -rf db ./log/* && nohup ./tenon3 -f 0 -g 0 &
cd /root/n4 &&  rm -rf db ./log/* && nohup ./tenon4 -f 0 -g 0 &
exit 0
sleep 3
cd /root/nodes/s11/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s12/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s13/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s14/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s15/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s16/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s17/ && nohup ./tenon -f 0 -g 0 &
cd /root/nodes/s18/ && nohup ./tenon -f 0 -g 0 &
