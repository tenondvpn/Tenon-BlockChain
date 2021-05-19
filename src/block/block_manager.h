#pragma once

#include <deque>

#include "common/config.h"
#include "common/min_heap.h"
#include "db/db.h"
#include "transport/proto/transport.pb.h"
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
    int AddNewBlock(
        const bft::protobuf::Block& block_item,
        db::DbWriteBach& db_batch);
    std::string GetCurrentShardBlockHashWithHeight(uint64_t height, const std::string& from);

private:
    BlockManager();
    ~BlockManager();
    void HandleMessage(transport::protobuf::Header& header);
    int HandleGetBlockRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void HandleGetHeightRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void HandleAttrGetRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void HandleGetAccountInitRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void HandleAdRewardRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg);
    void SendBlockNotExists(transport::protobuf::Header& header);
    std::string* GetHeightBlockWithCache(uint64_t height);
    void SaveHeightBlockWithCache(uint64_t height, std::string* block_data);
    void SendBlockResponse(transport::protobuf::Header& header, const std::string& block_str);
    int64_t FixRewardWithHistory(const std::string& id, int64_t new_amount);

    static const uint32_t kCacheBlockSize = 1024;
    std::unordered_map<uint64_t, std::pair<std::string*, int32_t>> height_chain_map_;
    common::MinHeap<HeightCacheHeapItem, kCacheBlockSize> height_cache_heap_{ false };
    std::mutex cache_height_block_mutex_;
    std::unordered_map<std::string, int64_t> account_reward_map_;
    std::mutex account_reward_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(BlockManager);
};

}  // namespace block

}  // namespace tenon

