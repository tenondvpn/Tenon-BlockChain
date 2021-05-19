#include "stdafx.h"
#include "ip/cidr.h"

#ifdef _WIN32
#include <winsock2.h>
#endif // _WIN32

#include <cstdlib>
#include <cassert>
#include <bitset>

#include "common/split.h"
#include "common/string_utils.h"

namespace tenon {

namespace ip {

Cidr::Cidr() {}

Cidr::~Cidr() {}

#ifdef _WIN32

const wchar_t *GetWC(const char *c) {
    const size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, c, cSize);

    return wc;
}

int inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    int size = sizeof(ss);
    ZeroMemory(&ss, sizeof(ss));
#ifdef _WIN32
    wchar_t src_copy[INET6_ADDRSTRLEN + 1];
    const size_t cSize = strlen(src) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, src, cSize);
    wcsncpy(src_copy, wc, INET6_ADDRSTRLEN + 1);
    delete []wc;
#else
    char src_copy[INET6_ADDRSTRLEN + 1];
    strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
#endif
    /* stupid non-const API */
    src_copy[INET6_ADDRSTRLEN] = 0;

    if (WSAStringToAddressW(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
        switch (af) {
        case AF_INET:
            *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
            return 1;
        case AF_INET6:
            *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
            return 1;
        }
    }
    return 0;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;

    ZeroMemory(&ss, sizeof(ss));
    ss.ss_family = af;

    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
        break;
    default:
        return NULL;
    }
    /* cannot direclty use &size because of strict aliasing rules */
#ifdef _WIN32
    const size_t cSize = strlen(dst) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, dst, cSize);
    char* res = (WSAAddressToStringW((struct sockaddr *)&ss, sizeof(ss), NULL, wc, &s) == 0) ?
        dst : NULL;
    delete[]wc;
    return res;
#else
    return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0) ?
        dst : NULL;
#endif
}
#endif // _WIN32

in_addr_t Cidr::Netmask(int prefix) {
    return prefix == 0 ? 0 : ~(in_addr_t)0 << (32 - prefix);
}

in_addr_t Cidr::atoh(char *s) {
#ifdef _WIN32
    struct in_addr in;
    if (inet_pton(AF_INET, s, &in.s_addr) != 1) {
        return 0;
    }
    return ntohl(in.s_addr);
#else
    struct in_addr in;
    if (inet_aton(s, &in) == 0) {
        return 0;
    }
    return ntohl(in.s_addr);
#endif
}

int Cidr::ParseCidr(in_addr_t *addr, in_addr_t *mask, char *str) {
    char *p;
    int prefix;
    *mask = 0;
    prefix = 32;
    p = strchr(str, '/');
    if (p != NULL) {
        *p = '\0';
        if (strlen(str) < 7) {
            return kIpError;
        }

        prefix = atoi(p + 1);
        if (prefix < 0) {
            prefix = 0;
        }

        if (prefix > 32) {
            prefix = 32;
        }

        *addr = atoh(str);
        *mask = Netmask(prefix);
        return kIpSuccess;
    }

    return kIpError;
}

int Cidr::Init(const std::string& file_path) {
    FILE *fp = fopen(file_path.c_str(), "r");
    if (fp == NULL) {
        IP_ERROR("open ip file[%s] failed!", file_path.c_str());
        return kIpError;
    }

    char buf[128];
    in_addr_t addr;
    in_addr_t mask;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        common::Split<> spliter(buf, '\t');
        if (spliter.Count() != 2) {
            continue;
        }

        common::Split<> mask_split(spliter[0], '/');
        if (ParseCidr(&addr, &mask, spliter[0]) != kIpSuccess) {
            continue;
        }

        if (addr == 0) {
            continue;
        }

        uint32_t prefix = addr & mask;
        cicd_map_[prefix] = std::make_pair(atoi(spliter[1]),atoi(mask_split[1])) ;
    }
    fclose(fp);
    return kIpSuccess;
}

uint32_t Cidr::GetGeoId(const std::string& ip) {
    in_addr_t addr = atoh((char*)ip.c_str());
    for (uint32_t i = 32; i > 6; --i) {
        in_addr_t mask = Netmask(i);
        uint32_t prefix = addr & mask;
        auto iter = cicd_map_.find(prefix);
        if (iter != cicd_map_.end() && iter->second.second == i) {
            return iter->second.first;
        }
    }
    return 0;
}

}  // namespace ip

}  // namespace tenon
