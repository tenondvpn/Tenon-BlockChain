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
    bool NewGidTxValid(const std::string& gid, TxItemPtr tx_ptr);
    bool NewGidTxValid(const std::string& gid, bft::protobuf::TxInfo& tx_info);
    TxItemPtr GetTx(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);
    std::string GetUniversalGid(
        bool add_to,
        uint32_t tx_type,
        uint32_t call_contract_step,
        const std::string& gid);

private:
    GidManager() {}
    ~GidManager() {}
    std::string CreateTxInfo(TxItemPtr tx_ptr);

    std::unordered_map<std::string, TxItemPtr> tx_map_;
    std::mutex tx_map_mutex_;
};

}  // namespace bft

}  // namespace tenon
