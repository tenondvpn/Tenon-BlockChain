#pragma once

#include "db/db.h"
#include "election/elect_utils.h"
#include "election/proto/elect.pb.h"

namespace tenon {

namespace elect {

class NodeHistoryCredit {
public:
    NodeHistoryCredit();
    ~NodeHistoryCredit();
    void OnNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block);
    int GetNodeHistoryCredit(const std::string& id, int32_t* credit);

private:
    static const int32_t kInitNodeCredit = 30;
    static const int32_t kMaxNodeCredit = 100;
    static const int32_t kMinNodeCredit = 0;

    void ChangeCredit(const std::string& id, bool weedout, db::DbWriteBach& write_batch);

    std::mutex mutex_;
    std::unordered_map<std::string, int32_t> credit_map_;

    DISALLOW_COPY_AND_ASSIGN(NodeHistoryCredit);
};

}  // namespace elect

}  // namespace tenon