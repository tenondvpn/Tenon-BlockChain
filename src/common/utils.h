#pragma once

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <string>
#include <chrono>
#include <thread>

#include "common/log.h"

#ifndef DISALLOW_COPY_AND_ASSIGN
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
        TypeName(const TypeName&); \
        TypeName& operator=(const TypeName&)
#endif  // !DISALLOW_COPY_AND_ASSIGN

#ifdef LEGO_TRACE_MESSAGE
struct Construct {
    uint32_t net_id;
    uint8_t country;
    uint8_t reserve1;
    uint8_t reserve2;
    uint8_t reserve3;
    char hash[24];
};

#define LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(message, append) \
    do { \
        if ((message).has_debug()) { \
            Construct* src_cons_key = (Construct*)((message).src_dht_key().c_str()); \
            Construct* des_cons_key = (Construct*)((message).des_dht_key().c_str()); \
            TENON_ERROR("[%s][handled: %d] [hash: %llu][hop: %d][src_net: %u][des_net: %u][id:%u]" \
                "[broad: %d][universal: %d][type: %d] %s", \
                (message).debug().c_str(), \
                (message).handled(), \
                (message).hash(), \
                (message).hop_count(), \
                src_cons_key->net_id, \
                des_cons_key->net_id, \
                (message).id(), \
                (message).has_broadcast(), \
                (message).universal(), \
                (message).type(), \
                (std::string(append)).c_str()); \
        } \
    } while (0)
#else
#define LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(message, append)
#endif

namespace tenon {

namespace common {

enum MessageType {
    kDhtMessage = 0,
    kNatMessage = 1,
    kNetworkMessage = 2,
    kSyncMessage = 3,
    kBftMessage = 4,
    kElectMessage = 5,
    kServiceMessage = 6,
    kBlockMessage = 7,
    kRelayMessage = 8,  // any not handle (message) will routing by root
    kContractMessage = 9,
    kSubscriptionMessage = 10,
    kUdpDemoTestMessage = 11,
    kRefreshVpnNodesMessage = 12,
    kVpnRelayMessage = 13,
    kVssMessage = 14,
    kTtimeBlockMessage = 15,
    // max (message) type
    kLegoMaxMessageTypeCount,
};

enum CommonErrorCode {
    kCommonSuccess = 0,
    kCommonError = 1,
};

enum GetHeightBlockType {
	kHeightBlockTransactions = 0,
	kHeightBlockVersion = 1,
};

static const uint32_t kImmutablePoolSize = 256u;
static const uint32_t kRootChainPoolIndex = kImmutablePoolSize;
static const uint32_t kInvalidPoolIndex = kImmutablePoolSize + 1;
static const uint32_t kTestForNetworkId = 4u;
extern volatile bool global_stop;
static const uint16_t kDefaultVpnPort = 9033u;
static const uint16_t kDefaultRoutePort = 9034u;
static const int64_t kRotationPeriod = 60ll * 1000ll * 1000ll;
static const uint32_t kMaxRotationCount = 4u;
static const uint16_t kNodePortRangeMin = 1000u;
static const uint16_t kNodePortRangeMax = 10000u;
static const uint16_t kVpnServerPortRangeMin = 10000u;
static const uint16_t kVpnServerPortRangeMax = 35000u;
static const uint16_t kVpnRoutePortRangeMin = 35000u;
static const uint16_t kVpnRoutePortRangeMax = 65000u;
static const uint16_t kRouteUdpPortRangeMin = 65000u;
static const uint16_t kRouteUdpPortRangeMax = 65100u;
static const uint16_t kVpnUdpPortRangeMin = 65100u;
static const uint16_t kVpnUdpPortRangeMax = 65200u;
static const uint64_t kTimeBlockCreatePeriodSeconds = 10llu;
static const uint32_t kEatchShardMaxSupperLeaderCount = 7u;
static const uint32_t kEachShardMinNodeCount = 3u;
static const uint32_t kEachShardMaxNodeCount = 1024u;

static const int64_t kInvalidInt64 = (std::numeric_limits<int64_t>::max)();
static const uint64_t kInvalidUint64 = (std::numeric_limits<uint64_t>::max)();
static const uint32_t kInvalidUint32 = (std::numeric_limits<uint32_t>::max)();
static const uint32_t kInvalidFloat = (std::numeric_limits<float>::max)();

uint32_t GetPoolIndex(const std::string& acc_addr);
std::string CreateGID(const std::string& pubkey);
std::string FixedCreateGID(const std::string& str);
inline static std::string GetTxDbKey(bool from, const std::string& gid) {
    if (from) {
        return std::string("TX_from_") + gid;
    } else {
        return std::string("TX_to_") + gid;
    }
}

inline static std::string GetHeightDbKey(
        uint32_t netid,
        uint32_t pool_index,
        uint64_t height) {
    return std::string("H_" + std::to_string(netid) + "_" +
            std::to_string(pool_index) + "+" + std::to_string(height));
}

inline static std::string TimestampToDatetime(time_t timestamp) {
    struct tm* p = localtime(&timestamp);
    char time_str[64];
    memset(time_str, 0, sizeof(time_str));
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", p);
    return time_str;
}

inline static std::string MicTimestampToLiteDatetime(int64_t timestamp) {
#ifndef _WIN32
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm* now = std::gmtime(&tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%02d/%02d %02d:%02d",
            now->tm_mon + 1,
            now->tm_mday,
            now->tm_hour,
            now->tm_min);
    return time_str;
#else
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    __time64_t tt = std::chrono::system_clock::to_time_t(tp);
    struct tm  now;
    _localtime64_s(&now, &tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%02d/%02d %02d:%02d",
            now.tm_mon + 1,
            now.tm_mday,
            now.tm_hour,
            now.tm_min);
    return time_str;
#endif
}

inline static std::string MicTimestampToDatetime(int64_t timestamp) {
#ifndef _WIN32
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm* now = std::gmtime(&tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%4d/%02d/%02d %02d:%02d:%02d",
            now->tm_year + 1900,
            now->tm_mon + 1,
            now->tm_mday,
            now->tm_hour,
            now->tm_min,
            now->tm_sec);
    return time_str;
#else
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    __time64_t tt = std::chrono::system_clock::to_time_t(tp);
    struct tm  now;
    _localtime64_s(&now, &tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%4d/%02d/%02d %02d:%02d:%02d",
            now.tm_year + 1900,
            now.tm_mon + 1,
            now.tm_mday,
            now.tm_hour,
            now.tm_min,
            now.tm_sec);
    return time_str;
#endif
}

uint32_t RandomCountry();

void itimeofday(long *sec, long *usec);
int64_t iclock64(void);
uint32_t iclock();
void SignalRegister();
uint16_t GetNodePort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port);
uint16_t GetVpnServerPort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port);
uint16_t GetVpnRoutePort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port);
uint16_t GetUdpRoutePort(
        const std::string& dht_key,
        uint32_t timestamp_days,
        uint16_t min_port,
        uint16_t max_port);
std::string IpUint32ToString(uint32_t int_ip);
uint32_t IpStringToUint32(const std::string& str_ip);
int RemoteReachable(const std::string& ip, uint16_t port, bool* reachable);
bool IsVlanIp(const std::string& ip);

}  // namespace common

}  // namespace tenon

