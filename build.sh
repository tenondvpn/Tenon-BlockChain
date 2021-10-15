# configure
export CXX=/root/tools/gcc-8.3.0/install/bin/g++
export CC=/root/tools/gcc-8.3.0/install/bin/gcc
TARGET=Debug
mkdir -p cbuild_$TARGET
cd cbuild_$TARGET
# CMAKE_BUILD_TYPE:
#   None:
#   Debug:              -g
#   Release:            -O3 -DNDEBUG
#   RelWithDebInfo:     -O2 -g -DNDEBUG
#   MinSizeRel:         -Os -DNDEBUG
cmake .. -DCMAKE_BUILD_TYPE=$TARGET -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2r -DCMAKE_INSTALL_PREFIX=~/tenon

# make
make -j4 tenon
