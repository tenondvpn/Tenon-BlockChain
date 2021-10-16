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
