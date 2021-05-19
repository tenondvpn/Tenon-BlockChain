#include "stdafx.h"
#include "transport/endpoint.h"

namespace std {
    bool operator==(
        const tenon::transport::Endpoint& lhs,
        const tenon::transport::Endpoint& rhs) {
        return lhs.ip == rhs.ip && lhs.port == rhs.port;
    }
}
