# configure
export CXX=/root/install/bin/g++
export CC=/root/install/bin/gcc
TARGET=Debug
mkdir -p cbuild_$TARGET
cd cbuild_$TARGET
# CMAKE_BUILD_TYPE:
#   None:
#   Debug:              -g
#   Release:            -O3 -DNDEBUG
#   RelWithDebInfo:     -O2 -g -DNDEBUG
#   MinSizeRel:         -Os -DNDEBUG
cmake .. -DCMAKE_BUILD_TYPE=$TARGET -DOPENSSL_ROOT_DIR=./third_party/depends/include/ -DCMAKE_INSTALL_PREFIX=~/tenon

# make
make -j4 tenon
#strip tenon
#make -j4 vpn_client
