#pragma once

#include <deque>

#include "common/config.h"
#include "common/limit_hash_set.h"
#include "db/db.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "bft/proto/bft.pb.h"
#include "block/block_utils.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace block {

struct HeightCacheHeapItem {
    uint64_t height;
    uint32_t cache_count;
};

bool operator<(HeightCacheHeapItem& lhs, HeightCacheHeapItem& rhs);
bool operator==(HeightCacheHeapItem& lhs, HeightCacheHeapItem& rhs);

}  // namespace block

}  // namespace tenon

namespace std {
template<>
struct hash<tenon::block::HeightCacheHeapItem> {
    size_t operator()(const tenon::block::HeightCacheHeapItem& _Keyval) const noexcept {
        return _Keyval.height;
    }
};
}


namespace tenon {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const tenon::block::HeightCacheHeapItem& val);

}  // namespace common

}  // namespace tenon

namespace tenon {

namespace block {

class BlockManager {
public:
    static BlockManager* Instance();
    int Init(common::Config& conf);
    int AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_item, db::DbWriteBach& db_batch, bool to_cache);
    int GetBlockWithHeight(
        uint32_t network_id,
        uint32_t pool_index,
        uint64_t height,
        bft::protobuf::Block& block_item);
//     bool BlockExists(const std::string& hash);

private:
    BlockManager();
    ~BlockManager();
    void HandleMessage(transport::TransportMessagePtr& header);
    int HandleGetBlockRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void HandleGetHeightRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
//     void HandleGetAccountInitRequest(
//         transport::protobuf::Header& header,
//         protobuf::BlockMessage& block_msg);
    void HandleAdRewardRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void SendBlockNotExists(transport::protobuf::Header& header);
    void SendBlockResponse(transport::protobuf::Header& header, const std::string& block_str);
    int64_t FixRewardWithHistory(const std::string& id, int64_t new_amount);
    int InitRootSingleBlocks();
    int InitRootElectBlocks();
    int InitRootTimeBlocks();

    static const uint32_t kCacheBlockSize = 1024;
    std::unordered_map<std::string, int64_t> account_reward_map_;
    std::mutex account_reward_map_mutex_;
    common::LimitHashSet<std::string> block_hash_limit_set_{ 2048u };

    DISALLOW_COPY_AND_ASSIGN(BlockManager);
};

}  // namespace block

}  // namespace tenon

