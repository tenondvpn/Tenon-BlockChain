#pragma once

#include <limits>

#include "common/utils.h"
#include "common/log.h"
#include "common/hash.h"
#include "common/global_info.h"
#include "common/thread_safe_queue.h"
#include "bft/proto/bft.pb.h"
#include "db/db.h"
#include "transport/transport_utils.h"

#define BFT_DEBUG(fmt, ...) TENON_DEBUG("[bft]" fmt, ## __VA_ARGS__)
#define BFT_INFO(fmt, ...) TENON_INFO("[bft]" fmt, ## __VA_ARGS__)
#define BFT_WARN(fmt, ...) TENON_WARN("[bft]" fmt, ## __VA_ARGS__)
#define BFT_ERROR(fmt, ...) TENON_ERROR("[bft]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace bft {

enum BftErrorCode {
    kBftSuccess = 0,
    kBftError = 1,
    kBftAdded = 2,
    kBftNotExists = 4,
    kBftTxAdded = 5,
    kBftNoNewTxs = 6,
    kBftInvalidPackage = 7,
    kBftTxNotExists = 8,
    kBftAccountNotExists = 9,
    kBftAccountBalanceError = 10,
    kBftAccountExists = 11,
    kBftBlockHashError = 12,
    kBftBlockHeightError = 13,
    kBftPoolIndexError = 14,
    kBftBlockNotExists = 15,
    kBftBlockPreHashError = 16,
    kBftNetwokInvalid = 17,
    kBftLeaderInfoInvalid = 18,
    kBftExecuteContractFailed = 19,
    kBftGasUsedNotEqualToLeaderError = 20,
    kBftUserSetGasLimitError = 21,
    kBftCreateContractKeyError = 22,
    kBftContractAddressLocked = 23,
    kBftContractBytesCodeError = 24,
    kBftTimeBlockHeightError = 25,
    kBftElectBlockHeightError = 26,
    kBftLeaderTxInfoInvalid = 27,
    kBftVssRandomNotMatch = 28,
};

enum BftStatus {
    kBftInit = 0,
    kBftPrepare = 1,
    kBftPreCommit = 2,
    kBftCommit = 3,
    kBftCommited = 4,
    kBftToTxInit = 5,
    kBftRootBlock = 6,
    kBftCallContract = 7,
    kBftStepTimeout = 8,
    kBftSyncBlock = 9,
};

enum BftRole {
    kBftRootCongress = 0,
    kBftShard = 1,
};

enum BftLeaderCheckStatus {
    kBftWaitingBackup = 0,
    kBftOppose = 1,
    kBftAgree = 2,
    kBftHandled = 3,
    kBftReChallenge = 4,
};

enum BftCheckTimeoutStatus {
    kTimeoutNormal = 0,
    kTimeout = 1,
    kTimeoutCallPrecommit = 2,
    kTimeoutCallReChallenge = 3,
    kTimeoutWaitingBackup = 4,
};

enum WaitingBlockType {
    kRootBlock,
    kSyncBlock,
    kToBlock,
};

struct BftItem {
    transport::TransportMessagePtr header_ptr;
    bft::protobuf::BftMessage bft_msg;
    bool prepare_valid{ true };
};

typedef std::shared_ptr<BftItem> BftItemPtr;
typedef std::shared_ptr<bft::protobuf::Block> BlockPtr;

struct BlockToDbItem {
    BlockToDbItem(BlockPtr& bptr)
        : block_ptr(bptr) {}
    BlockPtr block_ptr;
    db::DbWriteBach db_batch;
    bool is_kv_synced{ false };
};

struct WaitingBlockItem {
    WaitingBlockItem(BlockPtr& bptr, uint32_t t) : block_ptr(bptr), type(t) {}
    BlockPtr block_ptr;
    uint32_t type;
};

struct LeaderPrepareItem {
    std::shared_ptr<bft::protobuf::TbftLeaderPrepare> prpare_block{ nullptr };
    std::vector<libff::alt_bn128_G1> backup_sign;
    std::unordered_set<std::string> precommit_aggree_set_;
    common::Bitmap prepare_bitmap_{ common::kEachShardMaxNodeCount };
    libff::alt_bn128_G1 backup_precommit_signs_[common::kEachShardMaxNodeCount];
};

typedef std::shared_ptr<BlockToDbItem> BlockToDbItemPtr;
typedef std::shared_ptr<WaitingBlockItem> WaitingBlockItemPtr;
typedef common::ThreadSafeQueue<BlockToDbItemPtr> BlockQueue;
typedef common::ThreadSafeQueue<WaitingBlockItemPtr> WaitingBlockQueue;

static const uint32_t kBftOneConsensusMaxCount = 32u;  // every consensus
static const uint32_t kBftOneConsensusMinCount = 1u;
// bft will delay 500ms for all node ready
static const uint32_t kBftStartDeltaTime = 500000u;
static const uint32_t kBftFinalStatisticStartDeltaTime = 500000u;
static const uint32_t kBftElectionStartDeltaTime = 500000u;

// broadcast default param
static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;
static const uint32_t kBftTimeout = 14u * 1000u * 1000u;  // bft timeout 15s
// tx pool timeout 3 * kTimeBlockCreatePeriodSeconds seconds
static const uint32_t kTxPoolTimeoutSeconds = 30u;
static const uint32_t kTxPoolFinalStatisticTimeoutSeconds = /*kBftFinalStatisticStartDeltaTime / 1000000u + */30u;
static const uint32_t kTxPoolElectionTimeoutSeconds = /*kBftElectionStartDeltaTime / 1000000u + */30u;
static const uint32_t kBftTimeoutCheckPeriod = 10u * 1000u * 1000u;
static const uint32_t kBftLeaderPrepareWaitPeriod = 5u * 1000u * 1000u;
static const uint32_t kPrevTransportVersion = 0;
static const uint32_t kTransportVersion = 1;
static const int64_t kChangeLeaderTimePeriodSec = 30l;

static const std::string kVpnSubscriptionDeduction("vpn_subscription_deduction");
static const std::string kRootCreateNewAccountAttrKey("kRootNewAddr_netid");

// transaction contract attr keys
static const std::string kContractAddress = "__caddress";
static const std::string kContractBytesCode = "__cbytescode";
static const std::string kContractSourceCode = "__csourcecode";
static const std::string kContractBytesStartCode = "60806040";
static const std::string kContractName = "__ctname";
static const std::string kContractDesc = "__ctdesc";
static const std::string kContractCreatedBytesCode = "__cbytescodecreated";
static const std::string kContractInputCode = "__cinput";
static const std::string kContractCallerbalance = "__ccontractcallerbalance";
static const std::string kContractCallerChangeAmount = "__ccontractcallerchangeamount";
static const std::string kContractCallerGasUsed = "__ccontractcallergasused";
static const std::string kStatisticAttr = "__statisticattr";

// gas consume
static const uint64_t kTransferGas = 1000llu;
static const uint64_t kCallContractDefaultUseGas = 10000llu;
static const uint64_t kKeyValueStorageEachBytes = 100llu;

std::string StatusToString(uint32_t status);
// hash128(gid + from + to + amount + type + attrs(k:v))
std::string GetTxMessageHash(const protobuf::TxInfo& tx_info);
// prehash + network_id + height + random + elect version + txes's hash
std::string GetBlockHash(const protobuf::Block& block);
uint32_t NewAccountGetNetworkId(const std::string& addr);
bool IsRootSingleBlockTx(uint32_t tx_type);
bool IsShardSingleBlockTx(uint32_t tx_type);
bool IsShardSuperSingleBlockTx(uint32_t tx_type);

}  // namespace bft

}  //namespace tenon
