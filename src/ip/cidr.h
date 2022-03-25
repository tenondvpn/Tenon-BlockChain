#pragma once

#include <unordered_map>

#include "ip/ip_utils.h"

namespace tenon {

namespace ip {

class Cidr {
public:
    Cidr();
    ~Cidr();
    int Init(const std::string& file_path);
    uint32_t GetGeoId(const std::string& ip);

private:
    std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> cicd_map_;

    DISALLOW_COPY_AND_ASSIGN(Cidr);
};

}  // namespace ip

}  // namespace tenon
