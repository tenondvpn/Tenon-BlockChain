#include "stdafx.h"
#include "common/utils.h"

#include <signal.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <iostream>
#include <string>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <time.h>
#else
#include <sys/time.h>
#endif

#ifdef _MSC_VER
#define _WINSOCKAPI_
#include <windows.h>
#endif

#include "common/hash.h"
#include "common/random.h"
#include "common/country_code.h"
#include "common/global_info.h"
#include "common/time_utils.h"
#include "common/encode.h"
#include "common/split.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"

namespace tenon {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const tenon::common::BlockItemPtr& val) {
    return common::Hash::Hash64(val.item->gid + std::to_string(val.item->timestamp));
}

template<>
uint64_t MinHeapUniqueVal(const tenon::common::BlockItem& val) {
    return common::Hash::Hash64(val.gid + std::to_string(val.timestamp));
}

bool operator<(BlockItemPtr& lhs, BlockItemPtr& rhs) {
    return lhs.item->height < rhs.item->height;
}

bool operator<(BlockItem& lhs, BlockItem& rhs) {
    return lhs.height < rhs.height;
}

bool operator==(const BlockItemPtr& lhs, const BlockItemPtr& rhs) {
    return lhs.item->height == rhs.item->height;
}

}  // namespace common

}  // namespace tenon

namespace tenon {

namespace common {
    
volatile bool global_stop = false;

uint32_t GetPoolIndex(const std::string& acc_addr) {
    if (acc_addr == common::kRootChainSingleBlockTxAddress ||
            acc_addr == common::kRootChainTimeBlockTxAddress ||
            acc_addr == common::kRootChainElectionBlockTxAddress) {
        return kRootChainPoolIndex;
    }

    uint32_t pool_index = common::Hash::Hash32(acc_addr);
    pool_index %= kImmutablePoolSize;
    return pool_index;
}

std::string CreateGID(const std::string& pubkey) {
    std::string str = (pubkey + Random::RandomString(1024u));
    return common::Hash::Hash256(str);
}

std::string FixedCreateGID(const std::string& str) {
    return common::Hash::Hash256(str);
}

uint8_t RandomCountry() {
    return rand() % (FX + 1);
}

void itimeofday(long *sec, long *usec) {
#ifndef WIN32
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
#else
	static long mode = 0, addsec = 0;
	BOOL retval;
	static int64_t freq = 1;
	int64_t qpc;
	if (mode == 0) {
		retval = QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
		freq = (freq == 0) ? 1 : freq;
		retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
		addsec = (long)time(NULL);
		addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
		mode = 1;
	}
	retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
	retval = retval * 2;
	if (sec) *sec = (long)(qpc / freq) + addsec;
	if (usec) *usec = (long)((qpc % freq) * 1000000 / freq);
#endif
}

int64_t iclock64(void) {
	long s, u;
	int64_t value;
	itimeofday(&s, &u);
	value = ((int64_t)s) * 1000 + (u / 1000);
	return value;
}

uint32_t iclock() {
	return static_cast<uint32_t>(iclock64() & 0xfffffffful);
}

static void SignalCallback(int sig_int) {
    global_stop = true;
}

void SignalRegister() {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGINT, SignalCallback);
    signal(SIGTERM, SignalCallback);

    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
#endif
}

uint16_t GetVpnServerPort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port) {
    std::string tmp_str = dht_key + std::to_string(timestamp_days);
    uint32_t hash32 = common::Hash::Hash32(tmp_str);
    if (min_port == 0 || max_port == 0 || max_port <= min_port) {
        min_port = kVpnServerPortRangeMin;
        max_port = kVpnServerPortRangeMax;
    }

    uint32_t vpn_server_range = max_port - min_port;
    uint16_t tmp_port = (hash32 % vpn_server_range) + min_port;
    return tmp_port;
}

uint16_t GetNodePort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port) {
    std::string tmp_str = dht_key + std::to_string(timestamp_days);
    uint32_t hash32 = common::Hash::Hash32(tmp_str);
    if (min_port == 0 || max_port == 0 || max_port <= min_port) {
        min_port = kNodePortRangeMin;
        max_port = kNodePortRangeMax;
    }

    uint32_t node_range = max_port - min_port;
    uint16_t tmp_port = (hash32 % node_range) + min_port;
    return tmp_port;
}

uint16_t GetVpnRoutePort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port) {
    std::string tmp_str = dht_key + std::to_string(timestamp_days);
    uint32_t hash32 = common::Hash::Hash32(tmp_str);
    if (min_port == 0 || max_port == 0 || max_port <= min_port) {
        min_port = kVpnRoutePortRangeMin;
        max_port = kVpnRoutePortRangeMax;
    }

    uint32_t vpn_server_range = max_port - min_port;
    uint16_t tmp_port = (hash32 % vpn_server_range) + min_port;
    return tmp_port;
}

uint16_t GetUdpRoutePort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port) {
    std::string tmp_str = dht_key + std::to_string(timestamp_days);
    uint32_t hash32 = common::Hash::Hash32(tmp_str);
    if (min_port == 0 || max_port == 0 || max_port <= min_port) {
        min_port = kRouteUdpPortRangeMin;
        max_port = kRouteUdpPortRangeMax;
    }

    uint32_t vpn_server_range = max_port - min_port;
    uint16_t tmp_port = (hash32 % vpn_server_range) + min_port;
    return tmp_port;
}

bool IsVlanIp(const std::string& ip_str)
{
    /*-----------------------------------------
    局域网IP地址范围
    A类：10.0.0.0-10.255.255.255
    B类：172.16.0.0-172.31.255.255
    C类：192.168.0.0-192.168.255.255
    -------------------------------------------*/
    common::Split<> ip_dot(ip_str.c_str(), '.', ip_str.size());
    if (ip_dot.Count() != 4) {
        return false;
    }

    int32_t ip[2];
    if (!common::StringUtil::ToInt32(ip_dot[0], &ip[0])) {
        return false;
    }
    
    if (!common::StringUtil::ToInt32(ip_dot[1], &ip[1])) {
        return false;
    }

    if ((ip[0] == 10) ||
            (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
            (ip[0] == 192 && ip[1] == 168) ||
            (ip[0] == 0 && ip[1] == 0)) {
        return true;
    }
    
    return false;
}

}  // namespace common

}  // namespace tenon
