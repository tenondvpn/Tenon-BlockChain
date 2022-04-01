#pragma once

#include <unordered_map>

#include "ip/ip_utils.h"

namespace tenon {

namespace ip {

class IpWeight {
public:
    IpWeight() {}

    ~IpWeight() {}

    void AddIp(uint32_t ip) {
        for (int32_t i = 32; i > 6; --i) {
            in_addr_t mask = Netmask(i);
            uint32_t prefix = ip & mask;
            auto iter = ipcount_map_.find(prefix);
            if (iter != ipcount_map_.end()) {
                ++iter->second;
            } else {
                ipcount_map_[prefix] = 1;
            }
        }
    }

    int32_t GetIpCount(uint32_t addr, int32_t* prefix_len) {
        for (int32_t i = 32; i > 6; --i) {
            in_addr_t mask = Netmask(i);
            uint32_t prefix = addr & mask;
            auto iter = ipcount_map_.find(prefix);
            if (iter != ipcount_map_.end()) {
                *prefix_len = i;
                return iter->second;
            }
        }

        *prefix_len = 0;
        return 0;
    }

private:
    std::unordered_map<uint32_t, int32_t> ipcount_map_;

};

}  // namespace ip

}  // namespace tenon
