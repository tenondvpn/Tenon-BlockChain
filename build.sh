# configure
TARGET=Debug
mkdir -p cbuild_$TARGET
cd cbuild_$TARGET
# CMAKE_BUILD_TYPE:
#   None:
#   Debug:              -g
#   Release:            -O3 -DNDEBUG
#   RelWithDebInfo:     -O2 -g -DNDEBUG
#   MinSizeRel:         -Os -DNDEBUG
cmake .. -DCMAKE_BUILD_TYPE=$TARGET -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2r -DCMAKE_INSTALL_PREFIX=~/lego

# make
make -j4 lego
make -j4 vpn_proxy
make -j4 vpn_client
make -j4 tenonvpn

OS=`uname`
if [ "$OS" == "Darwin" ]
then
    mkdir -p libs
    find . -name "lib*.a" -and -not -name "libp2p.a"  -exec cp -f -- "{}" libs \;
fi
