#pragma once

#include <string>

#include "common/min_heap.h"
#include "common/encode.h"

namespace tenon {

namespace  common {

enum ConsensusType {
    kConsensusInvalidType = 0,
    kConsensusCreateGenesisConsensusNetwork,
    kConsensusCreateGenesisAcount,
    kConsensusCreateAcount,
    kConsensusCreateContract,
    kConsensusTransaction,
    kConsensusCallContract,
    kConsensusMining,
    kConsensusLogin,
    kConsensusKeyValue,
    kConsensusPayForCommonVpn,
    kConsensusVpnBandwidth,
    kConsensusVpnMining,
    kConsensusVpnMiningPayToNode,
};

enum ClientStatus {
    kValid = 0,
    kBandwidthFreeToUseExceeded = 1,
    kPayForExpired = 2,
    kServerOverLoaded = 3,
    kLoginByOtherTerminal = 4,
};


enum ClientPlatform {
    kUnknown = 0,
    kIos = 1,
    kAndroid = 2,
    kMac = 3,
    kWindows = 4,
};

enum VipLevel {
    kNotVip = 0,
    kVipLevel1 = 1,
    kVipLevel2 = 2,
    kVipLevel3 = 3,
    kVipLevel4 = 4,
    kVipLevel5 = 5,
};

struct BlockItem {
    uint64_t height;
    std::string gid;
    std::string block_hash;
    std::string from;
    std::string to;
    uint32_t type;
    uint64_t balance;
    uint64_t amount;
    uint64_t timestamp;
    uint32_t status;
    uint32_t version;
};

struct BlockItemPtr {
    BlockItem* item;
};

bool operator<(BlockItem& lhs, BlockItem& rhs);
bool operator<(BlockItemPtr& lhs, BlockItemPtr& rhs);
bool operator==(const BlockItemPtr& lhs, const BlockItemPtr& rhs);


template<>
uint64_t MinHeapUniqueVal(const tenon::common::BlockItemPtr& val);

template<>
uint64_t MinHeapUniqueVal(const tenon::common::BlockItem& val);


static const std::string kClientFreeBandwidthOver = "bwo";
static const std::string kServerClientOverload = "sol";
static const std::string kCountryInvalid = "cni";
static const std::string kClientIsNotVip = "nvp";

static const std::string kVpnLoginAttrKey = "vpn_login";
static const std::string kUserPayForVpn = "user_pay_for_vpn";
static const std::string kCheckVpnVersion = "tenon_vpn_url";
static const std::string kSetValidVpnClientAccount = "set_valid_vpn_client_account";
static const std::string kIncreaseVpnBandwidth = "kIncreaseVpnBandwidth";
static const std::string kVpnMiningBandwidth = "kVpnMiningBandwidth";
static const std::string kVpnClientLoginAttr = "kVpnClientLoginAttr";
static const std::string kActiveUser = "kActiveUser";
static const std::string kDefaultEnocdeMethod = "aes-128-cfb";
static const std::string kAdRewardVersionStr = "5.1.0";
static const std::string kVpnVipNodeTag = "tvip";

static const std::string kVpnAdminAccount = "e8a1ceb6b807a98a20e3aa10aa2199e47cbbed08c2540bd48aa3e1e72ba6bd99";
static const std::string kVpnLoginManageAccount = "008817d7557fc65cec2c212a6a8bde3e3b8672331c6e206a60dceb60391d71b8";
static const std::string kCreateGenesisNetwrokAccount = common::Encode::HexDecode(
    "b5be6f0090e4f5d40458258ed9adf843324c0327145c48b55091f33673d2d5a4");

static const uint32_t kVpnShareStakingPrice = 1u;

static const uint64_t kTenonMiniTransportUnit = 100000000llu;
static const uint64_t kTenonMaxAmount = 210llu * 100000000llu * kTenonMiniTransportUnit;
static const uint32_t kTransactionNoVersion = 0u;
static const uint32_t kTransactionVersion = 1u;

static const uint64_t kVpnVipMinPayfor = 66llu * kTenonMiniTransportUnit;
static const uint64_t kVpnVipMaxPayfor = 2000u * kTenonMiniTransportUnit;

}  // namespace  common

}  // namespace tenon 

namespace std {
    template<>
    struct hash<tenon::common::BlockItemPtr> {
        size_t operator()(const tenon::common::BlockItemPtr& _Keyval) const noexcept {
            return _Keyval.item->height;
        }
    };
}

