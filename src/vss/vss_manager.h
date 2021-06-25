#pragma once

#include <mutex>
#include <atomic>

#include "common/utils.h"
#include "common/tick.h"
#include "election/elect_utils.h"
#include "security/public_key.h"
#include "transport/proto/transport.pb.h"
#include "vss/random_num.h"
#include "vss/proto/vss.pb.h"

namespace tenon {

namespace vss {

class VssManager {
public:
    static VssManager* Instance();
    void OnTimeBlock(
        uint64_t tm_block_tm,
        uint64_t tm_height,
        uint64_t elect_height,
        uint64_t epoch_random);
    uint64_t EpochRandom();
    uint64_t GetAllVssValid();
   
private:
    VssManager() {}
    ~VssManager() {}

    void ClearAll();
    void CheckVssPeriods();
    void CheckVssFirstPeriods();
    void CheckVssSecondPeriods();
    void CheckVssThirdPeriods();
    bool IsVssFirstPeriods();
    bool IsVssSecondPeriods();
    bool IsVssThirdPeriods();
    void BroadcastFirstPeriodHash();
    void BroadcastFirstPeriodSplitRandom();
    void BroadcastSecondPeriodRandom();
    void BroadcastThirdPeriodSplitRandom();
    void HandleFirstPeriodHash(const protobuf::VssMessage& vss_msg);
    void HandleFirstPeriodSplitRandom(const protobuf::VssMessage& vss_msg);
    void HandleSecondPeriodRandom(const protobuf::VssMessage& vss_msg);
    void HandleThirdPeriodSplitRandom(const protobuf::VssMessage& vss_msg);
    void HandleMessage(transport::protobuf::Header& header);

    RandomNum local_random_{ true };
    RandomNum other_randoms_[common::kEachShardMaxNodeCount];
    uint64_t prev_tm_height_{ common::kInvalidUint64 };
    uint64_t prev_elect_height_{ 0 };
    uint32_t local_member_index_{ common::kEachShardMaxNodeCount };
    common::Tick vss_tick_;
    uint32_t local_index_{ elect::kInvalidMemberIndex };
    uint32_t member_count_{ 0 };
    std::mutex mutex_;
    std::atomic<uint64_t> latest_tm_block_tm_{ 0 };
    uint64_t prev_epoch_final_random_{ 0 };
    bool first_period_cheched_{ false };
    bool second_period_cheched_{ false };
    bool third_period_cheched_{ false };
    uint64_t epoch_random_{ 0 };
    
    DISALLOW_COPY_AND_ASSIGN(VssManager);
};

}  // namespace vss

}  // namespace tenon
