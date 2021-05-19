#pragma once

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <err.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif // !_WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    in_addr_t Netmask(int prefix);
    in_addr_t atoh(char *s);
    int ParseCidr(in_addr_t *addr, in_addr_t *mask, char *str);

    std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> cicd_map_;

    DISALLOW_COPY_AND_ASSIGN(Cidr);
};

}  // namespace ip

}  // namespace tenon
