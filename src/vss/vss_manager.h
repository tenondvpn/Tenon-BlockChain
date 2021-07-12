#pragma once

#include <mutex>
#include <atomic>

#include "common/utils.h"
#include "common/tick.h"
#include "election/elect_utils.h"
#include "security/public_key.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
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
    void OnElectBlock(uint32_t network_id, uint64_t elect_height);
    uint64_t EpochRandom();
    uint64_t GetConsensusFinalRandom();
   
private:
    VssManager();
    ~VssManager() {}

    // just two period and consensus with time block can also guarantee safety
    void ClearAll();
    void CheckVssPeriods();
    void CheckVssFirstPeriods();
    void CheckVssSecondPeriods();
    void CheckVssThirdPeriods();
    bool IsVssFirstPeriods();
    bool IsVssSecondPeriods();
    bool IsVssThirdPeriods();
    bool IsVssFirstPeriodsHandleMessage();
    bool IsVssSecondPeriodsHandleMessage();
    bool IsVssThirdPeriodsHandleMessage();
    void BroadcastFirstPeriodHash();
    void BroadcastSecondPeriodRandom();
    void BroadcastThirdPeriodRandom();
    void HandleFirstPeriodHash(const protobuf::VssMessage& vss_msg);
    void HandleSecondPeriodRandom(const protobuf::VssMessage& vss_msg);
    void HandleThirdPeriodRandom(const protobuf::VssMessage& vss_msg);
    void HandleMessage(transport::TransportMessagePtr& header);
    uint64_t GetAllVssValid();
    void SetConsensusFinalRandomNum(const std::string& id, uint64_t final_random_num);

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
    std::mutex final_consensus_nodes_mutex_;
    std::unordered_set<std::string> final_consensus_nodes_;
    std::unordered_map<uint64_t, uint32_t> final_consensus_random_count_;
    uint32_t max_count_{ 0 };
    uint64_t max_count_random_{ 0 };

    // for unit test
#ifdef TENON_UNITTEST
    transport::protobuf::Header first_msg_;
    transport::protobuf::Header second_msg_;
    transport::protobuf::Header third_msg_;
#endif

    DISALLOW_COPY_AND_ASSIGN(VssManager);
};

}  // namespace vss

}  // namespace tenon
