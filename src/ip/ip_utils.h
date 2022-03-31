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

#include "common/utils.h"
#include "common/log.h"

#define IP_DEBUG(fmt, ...) TENON_DEBUG("[ip]" fmt, ## __VA_ARGS__)
#define IP_INFO(fmt, ...) TENON_INFO("[ip]" fmt, ## __VA_ARGS__)
#define IP_WARN(fmt, ...) TENON_WARN("[ip]" fmt, ## __VA_ARGS__)
#define IP_ERROR(fmt, ...) TENON_ERROR("[ip]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace ip {

enum IpErrorCode {
    kIpSuccess = 0,
    kIpError = 1,
};

static const uint8_t kInvalidCountryCode = 255u;

#ifdef _WIN32

inline static const wchar_t *GetWC(const char *c) {
    const size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, c, cSize);

    return wc;
}

inline static int inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    int size = sizeof(ss);
    ZeroMemory(&ss, sizeof(ss));
#ifdef _WIN32
    wchar_t src_copy[INET6_ADDRSTRLEN + 1];
    const size_t cSize = strlen(src) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, src, cSize);
    wcsncpy(src_copy, wc, INET6_ADDRSTRLEN + 1);
    delete[]wc;
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

inline static const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
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

inline static in_addr_t Netmask(int prefix) {
    return prefix == 0 ? 0 : ~(in_addr_t)0 << (32 - prefix);
}

inline static in_addr_t atoh(const char *s) {
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

inline static int ParseCidr(in_addr_t *addr, in_addr_t *mask, char *str) {
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

inline static int ParseIp(in_addr_t *addr, in_addr_t *mask, char *str, int32_t prefix) {
    char *p;
    *mask = 0;
    p = strchr(str, '/');
    if (p != NULL) {
        *p = '\0';
        if (strlen(str) < 7) {
            return kIpError;
        }

        *addr = atoh(str);
        *mask = Netmask(prefix);
        return kIpSuccess;
    }

    return kIpError;
}

inline static uint32_t IpToUint32(const char* ip, int32_t net_mask) {
    return atoh(ip) & Netmask(net_mask);
}

inline static std::string Uint32ToIp(uint32_t ip) {
    char str_ip[32];
    snprintf(str_ip, sizeof str_ip, "%u.%u.%u.%u",
        (ip & 0xff000000) >> 24,
        (ip & 0x00ff0000) >> 16,
        (ip & 0x0000ff00) >> 8,
        (ip & 0x000000ff));
    return str_ip;
}

}  // namespace ip

}  // namespace tenon
