#pragma once

#include <map>
#include <unordered_map>

#include "common/utils.h"
#include "common/user_property_key_define.h"

namespace tenon {

namespace init {

class GenesisBlockInit {
public:
    GenesisBlockInit();
    ~GenesisBlockInit();
    int CreateGenesisBlocks(uint32_t net_id);

private:
    int CreateRootGenesisBlocks();
    int CreateShardGenesisBlocks(uint32_t net_id);
    void InitGenesisAccount();
    void GenerateRootAccounts();

    std::map<uint32_t, std::string> pool_index_map_;
    std::unordered_map<uint32_t, std::string> root_account_with_pool_index_map_;

    DISALLOW_COPY_AND_ASSIGN(GenesisBlockInit);
};

};  // namespace init

};  // namespace tenon
