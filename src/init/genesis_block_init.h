#pragma once

#include <map>
#include <vector>

#include "common/utils.h"
#include "common/user_property_key_define.h"
#include "dht/node.h"

namespace tenon {

namespace init {

class GenesisBlockInit {
public:
    GenesisBlockInit();
    ~GenesisBlockInit();
    int CreateGenesisBlocks(
        uint32_t net_id,
        const std::vector<dht::NodePtr>& root_genesis_nodes,
        const std::vector<dht::NodePtr>& cons_genesis_nodes);

private:
    int CreateRootGenesisBlocks(
        const std::vector<dht::NodePtr>& root_genesis_nodes,
        const std::vector<dht::NodePtr>& cons_genesis_nodes);
    int CreateShardGenesisBlocks(uint32_t net_id);
    void InitGenesisAccount();
    void GenerateRootAccounts();
    int GenerateRootSingleBlock(
        const std::vector<dht::NodePtr>& root_genesis_nodes,
        const std::vector<dht::NodePtr>& cons_genesis_nodes);
    int GenerateShardSingleBlock();
    int CreateElectBlock(
        uint32_t shard_netid,
        std::string& root_pre_hash,
        uint64_t height,
        FILE* root_gens_init_block_file,
        const std::vector<dht::NodePtr>& genesis_nodes);

    std::map<uint32_t, std::string> pool_index_map_;
    std::map<uint32_t, std::string> root_account_with_pool_index_map_;

    DISALLOW_COPY_AND_ASSIGN(GenesisBlockInit);
};

};  // namespace init

};  // namespace tenon
