#pragma once

#include <string>
#include <unordered_map>
#include <mutex>

#include "bft/tx_bft.h"

namespace lego {

namespace bft {

class GidManager {
public:
    static GidManager* Instance();
    bool NewGidTxValid(const std::string& gid, TxItemPtr& tx_ptr);
    TxItemPtr GetTx(bool add_to, const std::string& gid);

private:
    GidManager() {}
    ~GidManager() {}

    std::string CreateTxInfo(TxItemPtr& tx_ptr);
        
    std::unordered_map<std::string, TxItemPtr> tx_map_;
    std::mutex tx_map_mutex_;
};

}  // namespace bft

}  // namespace lego
