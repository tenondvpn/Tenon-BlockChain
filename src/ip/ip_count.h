#pragma once

#include <unordered_map>

#include "ip/ip_utils.h"

namespace tenon {

namespace ip {

class IpWeight {
public:
    IpWeight() {}

    ~IpWeight() {}

    void AddIp(const std::string& ip) {
        for (int32_t i = (int32_t)ip.size(); i >= 7; --i) {
            in_addr_t addr;
            in_addr_t mask;
            if (ParseIp(&addr, &mask, (char*)ip.c_str(), i) != kIpSuccess) {
                continue;
            }

            if (addr == 0) {
                continue;
            }

            uint32_t prefix = addr & mask;
            auto iter = ipcount_map_.find(prefix);
            if (iter != ipcount_map_.end()) {
                ++iter->second;
            } else {
                ipcount_map_[prefix] = 1;
            }
        }
    }

    int32_t GetIpCount(const std::string& ip) {
        in_addr_t addr = atoh((char*)ip.c_str());
        for (int32_t i = 32; i > 6; --i) {
            in_addr_t mask = Netmask(i);
            uint32_t prefix = addr & mask;
            auto iter = ipcount_map_.find(prefix);
            if (iter != ipcount_map_.end()) {
                return iter->second;
            }
        }

        return 0;
    }

private:
    std::unordered_map<uint32_t, int32_t> ipcount_map_;

    DISALLOW_COPY_AND_ASSIGN(IpWeight);
};

}  // namespace ip

}  // namespace tenon
