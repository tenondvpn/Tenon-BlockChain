#pragma once

#include "services/vpn_server/vpn_svr_utils.h"

namespace tenon {

namespace vpn {

class SocksServer {
public:
    SocksServer();
    ~SocksServer();

private:

    DISALLOW_COPY_AND_ASSIGN(SocksServer);
};

}  // namespace vpn

}  // namespace tenon
