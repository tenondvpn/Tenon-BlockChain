#pragma once

#include <string>
#include <unordered_map>
#include <mutex>

#include "bft/tx_bft.h"

namespace tenon {

namespace bft {

class GidManager {
public:
    static GidManager* Instance();
    bool NewGidTxValid(const std::string& gid, TxItemPtr& tx_ptr);
    bool NewGidTxValid(const std::string& gid, const bft::protobuf::TxInfo& tx_info, bool save_to_db);
    std::string GetUniversalGid(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);

private:
    GidManager() {}
    ~GidManager() {}
};

}  // namespace bft

}  // namespace tenon
