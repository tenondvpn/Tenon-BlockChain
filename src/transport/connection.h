#pragma once

#include <functional>
#include <string>

#include "transport/transport_utils.h"

namespace lego {

namespace transport {

class Connection {
public:

protected:
    Connection(const std::string& ip, uint16_t port) : ip_(ip), port_(port) {}

    virtual ~Connection() {}

    std::string ip_;
    uint16_t port_;
};

}  // namespace transport

}  // namespace lego
