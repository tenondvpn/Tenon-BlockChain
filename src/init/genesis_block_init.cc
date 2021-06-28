#include "init/genesis_block_init.h"

#include <cmath>

#include "common/encode.h"
#include "block/account_manager.h"
#include "init/init_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "bft/bft_manager.h"
#include "election/elect_utils.h"
#include "network/network_utils.h"
#include "root/root_utils.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/crypto_utils.h"
#include "security/secp256k1.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"

namespace tenon {

namespace init {

GenesisBlockInit::GenesisBlockInit() {}

GenesisBlockInit::~GenesisBlockInit() {}

int GenesisBlockInit::CreateGenesisBlocks(
        uint32_t net_id,
        const std::vector<dht::NodePtr>& root_genesis_nodes,
        const std::vector<dht::NodePtr>& cons_genesis_nodes) {
    for (uint32_t i = 0; i < root_genesis_nodes.size(); ++i) {
        root_bitmap_.Set(i);
    }

    for (uint32_t i = 0; i < cons_genesis_nodes.size(); ++i) {
        shard_bitmap_.Set(i);
    }

    if (net_id == network::kRootCongressNetworkId) {
        common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
        return CreateRootGenesisBlocks(root_genesis_nodes, cons_genesis_nodes);
    }

    common::GlobalInfo::Instance()->set_network_id(net_id);
    return CreateShardGenesisBlocks(net_id);
}

int GenesisBlockInit::CreateElectBlock(
        uint32_t shard_netid,
        std::string& root_pre_hash,
        uint64_t height,
        FILE* root_gens_init_block_file,
        const std::vector<dht::NodePtr>& genesis_nodes) {
    auto tenon_block = std::make_shared<bft::protobuf::Block>();
    auto tx_list = tenon_block->mutable_tx_list();
    auto tx_info = tx_list->Add();
    tx_info->set_type(common::kConsensusRootElectShard);
    tx_info->set_from(root::kRootChainSingleBlockTxAddress);
    tx_info->set_version(common::kTransactionVersion);
    tx_info->set_amount(0);
    tx_info->set_gas_limit(0);
    tx_info->set_gas_used(0);
    tx_info->set_balance(0);
    tx_info->set_status(bft::kBftSuccess);
    tx_info->set_network_id(shard_netid);
    auto all_exits_attr = tx_info->add_attr();
    elect::protobuf::ElectBlock ec_block;
    int32_t expect_leader_count = (int32_t)pow(2.0, (double)((int32_t)log2(double(genesis_nodes.size() / 3))));
    int32_t node_idx = 0;
    for (auto iter = genesis_nodes.begin(); iter != genesis_nodes.end(); ++iter) {
        auto in = ec_block.add_in();
        in->set_pubkey((*iter)->pubkey_str());
        in->set_pool_idx_mod_num(node_idx < expect_leader_count ? node_idx : -1);
        ++node_idx;
    }

    ec_block.set_leader_count(expect_leader_count);
    ec_block.set_shard_network_id(shard_netid);
    auto ec_block_attr = tx_info->add_attr();
    ec_block_attr->set_key(elect::kElectNodeAttrElectBlock);
    ec_block_attr->set_value(ec_block.SerializeAsString());
    tenon_block->set_prehash(root_pre_hash);
    tenon_block->set_version(common::kTransactionVersion);
    tenon_block->set_agg_pubkey("");
    tenon_block->set_agg_sign_challenge("");
    tenon_block->set_agg_sign_response("");
    tenon_block->set_pool_index(common::kRootChainPoolIndex);
    tenon_block->set_height(height);
    const auto& bitmap_data = root_bitmap_.data();
    for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
        tenon_block->add_bitmap(bitmap_data[i]);
    }

    tenon_block->set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block->set_hash(bft::GetBlockHash(*tenon_block));
    fputs((common::Encode::HexEncode(tenon_block->SerializeAsString()) + "\n").c_str(),
        root_gens_init_block_file);
    if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
        INIT_ERROR("AddGenisisBlock error.");
        return kInitError;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm_height;
    uint64_t tm_with_block_height;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        common::kRootChainPoolIndex,
        &pool_height,
        &pool_hash,
        &tm_height,
        &tm_with_block_height);
    if (res != block::kBlockSuccess) {
        INIT_ERROR("GetBlockInfo error.");
        return kInitError;
    }

    auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
        root::kRootChainSingleBlockTxAddress);
    if (account_ptr == nullptr) {
        INIT_ERROR("get address failed! [%s]",
            common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
        return kInitError;
    }

    uint64_t balance = 0;
    if (account_ptr->GetBalance(&balance), block::kBlockSuccess) {
        INIT_ERROR("get address balance failed! [%s]",
            common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
        return kInitError;
    }

    if (balance != 0) {
        INIT_ERROR("get address balance failed! [%s]",
            common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
        return kInitError;
    }

    uint64_t elect_height = 0;
    std::string elect_block_str;
    if (account_ptr->GetLatestElectBlock(
            shard_netid,
            &elect_height,
            &elect_block_str) != block::kBlockSuccess) {
        INIT_ERROR("get address elect block failed! [%s]",
            common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
        return kInitError;
    }

    root_pre_hash = bft::GetBlockHash(*tenon_block);
    return kInitSuccess;
}

int GenesisBlockInit::GenerateRootSingleBlock(
        const std::vector<dht::NodePtr>& root_genesis_nodes,
        const std::vector<dht::NodePtr>& cons_genesis_nodes) {
    FILE* root_gens_init_block_file = fopen("./root_blocks", "w");
    if (root_gens_init_block_file == nullptr) {
        return kInitError;
    }

    GenerateRootAccounts();
    uint64_t root_single_block_height = 0llu;
    // for root single block chain
    std::string root_pre_hash;
    {
        auto tenon_block = std::make_shared<bft::protobuf::Block>();
        auto tx_list = tenon_block->mutable_tx_list();
        auto tx_info = tx_list->Add();
        tx_info->set_version(common::kTransactionVersion);
        tx_info->set_gid(common::CreateGID(""));
        tx_info->set_from(root::kRootChainSingleBlockTxAddress);
        tx_info->set_from_pubkey("");
        tx_info->set_from_sign("");
        tx_info->set_to("");
        tx_info->set_amount(0);
        tx_info->set_balance(0);
        tx_info->set_gas_limit(0);
        tx_info->set_type(common::kConsensusCreateGenesisAcount);
        tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        tenon_block->set_prehash("");
        tenon_block->set_version(common::kTransactionVersion);
        tenon_block->set_agg_pubkey("");
        tenon_block->set_agg_sign_challenge("");
        tenon_block->set_agg_sign_response("");
        tenon_block->set_pool_index(common::kRootChainPoolIndex);
        tenon_block->set_height(root_single_block_height++);
        const auto& bitmap_data = root_bitmap_.data();
        for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
            tenon_block->add_bitmap(bitmap_data[i]);
        }

        tenon_block->set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block->set_hash(bft::GetBlockHash(*tenon_block));
        fputs((common::Encode::HexEncode(tenon_block->SerializeAsString()) + "\n").c_str(),
            root_gens_init_block_file);
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("AddGenisisBlock error.");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm_height;
        uint64_t tm_with_block_height;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("GetBlockInfo error.");
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
            root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address failed! [%s]",
                common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance), block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        if (balance != 0) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        root_pre_hash = bft::GetBlockHash(*tenon_block);
    }

    {
        auto tenon_block = std::make_shared<bft::protobuf::Block>();
        auto tx_list = tenon_block->mutable_tx_list();
        auto tx_info = tx_list->Add();
        tx_info->set_version(common::kTransactionVersion);
        tx_info->set_gid(common::CreateGID(""));
        tx_info->set_from(root::kRootChainSingleBlockTxAddress);
        tx_info->set_from_pubkey("");
        tx_info->set_from_sign("");
        tx_info->set_to("");
        tx_info->set_amount(0);
        tx_info->set_balance(0);
        tx_info->set_gas_limit(0);
        tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        tx_info->set_type(common::kConsensusRootTimeBlock);
        tx_info->set_from(root::kRootChainSingleBlockTxAddress);
        tx_info->set_gas_limit(0llu);
        tx_info->set_amount(0);
        tx_info->set_network_id(network::kRootCongressNetworkId);
        auto all_exits_attr = tx_info->add_attr();
        all_exits_attr->set_key(tmblock::kAttrTimerBlock);
        auto now_tm = common::TimeUtils::TimestampSeconds() - common::kTimeBlockCreatePeriodSeconds;
        all_exits_attr->set_value(std::to_string(now_tm));
        auto vss_random_attr = tx_info->add_attr();
        vss_random_attr->set_key(tmblock::kVssRandomAttr);
        vss_random_attr->set_value(std::to_string(now_tm));
        std::cout << "set init timestamp: " << now_tm << std::endl;
        tenon_block->set_prehash(root_pre_hash);
        tenon_block->set_version(common::kTransactionVersion);
        tenon_block->set_agg_pubkey("");
        tenon_block->set_agg_sign_challenge("");
        tenon_block->set_agg_sign_response("");
        tenon_block->set_pool_index(common::kRootChainPoolIndex);
        tenon_block->set_height(root_single_block_height++);
        const auto& bitmap_data = root_bitmap_.data();
        for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
            tenon_block->add_bitmap(bitmap_data[i]);
        }

        tenon_block->set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block->set_hash(bft::GetBlockHash(*tenon_block));
        auto tmp_str = tenon_block->SerializeAsString();
        bft::protobuf::Block tenon_block2;
        tenon_block2.ParseFromString(tmp_str);
        assert(tenon_block2.tx_list_size() > 0);
        fputs((common::Encode::HexEncode(tmp_str) + "\n").c_str(), root_gens_init_block_file);
        tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(1, now_tm, now_tm);
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("AddGenisisBlock error");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm_height;
        uint64_t tm_with_block_height;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("GetBlockInfo error");
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
            root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        if (balance != 0) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }
    }

    if (CreateElectBlock(
            network::kRootCongressNetworkId,
            root_pre_hash,
            root_single_block_height++,
            root_gens_init_block_file,
            root_genesis_nodes) != kInitSuccess) {
        INIT_ERROR("CreateElectBlock kRootCongressNetworkId failed!");
        return kInitError;
    }

    if (CreateElectBlock(
            network::kConsensusShardBeginNetworkId,
            root_pre_hash,
            root_single_block_height++,
            root_gens_init_block_file,
            cons_genesis_nodes) != kInitSuccess) {
        INIT_ERROR("CreateElectBlock kConsensusShardBeginNetworkId failed!");
        return kInitError;
    }

    fclose(root_gens_init_block_file);
    std::cout << "create root genesis blocks success." << std::endl;
    return kInitSuccess;
}

int GenesisBlockInit::GenerateShardSingleBlock() {
    FILE* root_gens_init_block_file = fopen("./root_blocks", "r");
    if (root_gens_init_block_file == nullptr) {
        return kInitError;
    }

    char data[2048];
    while (fgets(data, 2048, root_gens_init_block_file) != nullptr)
    {
        auto tenon_block = std::make_shared<bft::protobuf::Block>();
        std::string tmp_data(data, strlen(data) - 1);
        if (!tenon_block->ParseFromString(common::Encode::HexDecode(tmp_data))) {
            return kInitError;
        }

        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("add genesis block failed!");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm_height;
        uint64_t tm_with_block_height;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("get pool block info failed! [%u]", common::kRootChainPoolIndex);
            return kInitError;
        }

        auto address = root::kRootChainSingleBlockTxAddress;
        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address info failed! [%s]",
                common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        if (balance != 0) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(address).c_str());
            return kInitError;
        }
    }

    std::cout << "create shard genesis blocks success." << std::endl;
    return kInitSuccess;
}

std::string GenesisBlockInit::GetValidPoolBaseAddr(uint32_t network_id, uint32_t pool_index) {
    uint32_t id_idx = 0;
    while (true) {
        std::string addr = common::Encode::HexDecode(common::StringUtil::Format(
            "%04d%s%04d",
            network_id,
            common::kStatisticFromAddressMidllefix.c_str(),
            id_idx++));
        uint32_t pool_idx = common::GetPoolIndex(addr);
        if (pool_idx == pool_index) {
            return addr;
        }
    }
}

int GenesisBlockInit::CreateRootGenesisBlocks(
        const std::vector<dht::NodePtr>& root_genesis_nodes,
        const std::vector<dht::NodePtr>& cons_genesis_nodes) {
    GenerateRootAccounts();
    uint64_t genesis_account_balance = 0llu;
    uint64_t all_balance = 0llu;
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        auto tenon_block = std::make_shared<bft::protobuf::Block>();
        auto tx_list = tenon_block->mutable_tx_list();
        auto iter = root_account_with_pool_index_map_.find(i);
        std::string address = iter->second;
        {
            auto tx_info = tx_list->Add();
            tx_info->set_version(common::kTransactionVersion);
            tx_info->set_gid(common::CreateGID(""));
            tx_info->set_from(GetValidPoolBaseAddr(
                network::kRootCongressNetworkId,
                common::GetPoolIndex(address)));
            tx_info->set_from_pubkey("");
            tx_info->set_from_sign("");
            tx_info->set_to("");
            tx_info->set_amount(0);
            tx_info->set_balance(0);
            tx_info->set_gas_limit(0);
            tx_info->set_type(common::kConsensusCreateGenesisAcount);
            tx_info->set_network_id(network::kRootCongressNetworkId);
        }

        {
            auto tx_info = tx_list->Add();
            tx_info->set_version(common::kTransactionVersion);
            tx_info->set_gid(common::CreateGID(""));
            tx_info->set_from(address);
            tx_info->set_from_pubkey("");
            tx_info->set_from_sign("");
            tx_info->set_to("");
            tx_info->set_amount(genesis_account_balance);
            tx_info->set_balance(genesis_account_balance);
            tx_info->set_gas_limit(0);
            tx_info->set_type(common::kConsensusCreateGenesisAcount);
            tx_info->set_network_id(network::kRootCongressNetworkId);
        }
        
        tenon_block->set_prehash("");
        tenon_block->set_version(common::kTransactionVersion);
        tenon_block->set_agg_pubkey("");
        tenon_block->set_agg_sign_challenge("");
        tenon_block->set_agg_sign_response("");
        tenon_block->set_pool_index(iter->first);
        tenon_block->set_height(0);
        const auto& bitmap_data = root_bitmap_.data();
        for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
            tenon_block->add_bitmap(bitmap_data[i]);
        }

        tenon_block->set_timeblock_height(1);
        tenon_block->set_electblock_height(2);
        tenon_block->set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block->set_hash(bft::GetBlockHash(*tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("add genesis block failed!");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm_height;
        uint64_t tm_with_block_height;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            iter->first,
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("get pool block info failed! [%u]", iter->first);
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address info failed! [%s]",
                common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        if (balance != genesis_account_balance) {
            INIT_ERROR("get address balance failed! [%s]",
                common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        all_balance += balance;
    }

    if (all_balance != 0) {
        INIT_ERROR("balance all error[%llu][%llu]",
            all_balance, common::kGenesisFoundationMaxTenon);
        return kInitError;
    }

    return GenerateRootSingleBlock(root_genesis_nodes, cons_genesis_nodes);
}

int GenesisBlockInit::CreateShardGenesisBlocks(uint32_t net_id) {
    InitGenesisAccount();
    uint64_t genesis_account_balance = common::kGenesisFoundationMaxTenon / pool_index_map_.size();
    uint64_t all_balance = 0llu;
    for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
        auto tenon_block = std::make_shared<bft::protobuf::Block>();
        auto tx_list = tenon_block->mutable_tx_list();
        std::string address = iter->second;
        {
            auto tx_info = tx_list->Add();
            tx_info->set_version(common::kTransactionVersion);
            tx_info->set_gid(common::CreateGID(""));
            tx_info->set_from(GetValidPoolBaseAddr(
                network::kConsensusShardBeginNetworkId,
                common::GetPoolIndex(address)));
            tx_info->set_from_pubkey("");
            tx_info->set_from_sign("");
            tx_info->set_to("");
            tx_info->set_amount(0);
            tx_info->set_balance(0);
            tx_info->set_gas_limit(0);
            tx_info->set_type(common::kConsensusCreateGenesisAcount);
            tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        }

        {
            auto tx_info = tx_list->Add();
            tx_info->set_version(common::kTransactionVersion);
            tx_info->set_gid(common::CreateGID(""));
            tx_info->set_from(address);
            tx_info->set_from_pubkey("");
            tx_info->set_from_sign("");
            tx_info->set_to("");

            if (iter->first == common::kImmutablePoolSize - 1) {
                genesis_account_balance += common::kGenesisFoundationMaxTenon % pool_index_map_.size();
            }

            tx_info->set_amount(genesis_account_balance);
            tx_info->set_balance(genesis_account_balance);
            tx_info->set_gas_limit(0);
            tx_info->set_type(common::kConsensusCreateGenesisAcount);
            tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        }
        
        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm_height;
        uint64_t tm_with_block_height;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            iter->first,
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("GetBlockInfo error.");
            return kInitError;
        }

        tenon_block->set_prehash("");
        tenon_block->set_version(common::kTransactionVersion);
        tenon_block->set_agg_pubkey("");
        tenon_block->set_agg_sign_challenge("");
        tenon_block->set_agg_sign_response("");
        tenon_block->set_pool_index(iter->first);
        tenon_block->set_height(0);
        const auto& bitmap_data = root_bitmap_.data();
        for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
            tenon_block->add_bitmap(bitmap_data[i]);
        }

        tenon_block->set_timeblock_height(1);
        tenon_block->set_electblock_height(2);
        tenon_block->set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block->set_hash(bft::GetBlockHash(*tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("AddGenisisBlock error.");
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address failed! [%s]", common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        if (balance != genesis_account_balance) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(address).c_str());
            return kInitError;
        }

        all_balance += balance;
    }

    if (all_balance != common::kGenesisFoundationMaxTenon) {
        INIT_ERROR("all_balance != common::kGenesisFoundationMaxTenon failed! [%lu][%llu]",
            all_balance, common::kGenesisFoundationMaxTenon);
        return kInitError;
    }

    return GenerateShardSingleBlock();
}

void GenesisBlockInit::InitGenesisAccount() {
//     
//     while (pool_index_map_.size() < common::kImmutablePoolSize) {
//         security::PrivateKey prikey;
//         security::PublicKey pubkey(prikey);
//         std::string pubkey_str;
//         pubkey.Serialize(pubkey_str, false);
//         std::string prikey_str;
//         prikey.Serialize(prikey_str);
// 
//         std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
//         std::string address1 = security::Secp256k1::Instance()->ToAddressWithPrivateKey(prikey_str);
//         assert(address == address1);
//         auto pool_index = common::GetPoolIndex(address);
//         auto iter = pool_index_map_.find(pool_index);
//         if (iter != pool_index_map_.end()) {
//             continue;
//         }
// 
//         pool_index_map_.insert(std::make_pair(pool_index, prikey_str));
//     }
// 
//     for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end();  ++iter) {
//         std::cout << "11 pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(iter->second) << "\")));" << std::endl;
//     }

//     for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
//         std::cout << "pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(security::Secp256k1::Instance()->ToAddressWithPrivateKey(iter->second)) << "\")));" << std::endl;
//     }
    pool_index_map_.insert(std::make_pair(0, common::Encode::HexDecode("01cab67e8eca011d1ea49177807690fa5b9958c2")));
    pool_index_map_.insert(std::make_pair(1, common::Encode::HexDecode("d17ebfbb96e0546d59886f770930b43e6f88af41")));
    pool_index_map_.insert(std::make_pair(2, common::Encode::HexDecode("138a3ae5ac3bf1e104881fdc529869752ed08f36")));
    pool_index_map_.insert(std::make_pair(3, common::Encode::HexDecode("f604e042c613a1e61c541d93625e0d7c689296ec")));
    pool_index_map_.insert(std::make_pair(4, common::Encode::HexDecode("09805e35f49739719e1830ec4a494bde9d868945")));
    pool_index_map_.insert(std::make_pair(5, common::Encode::HexDecode("8e6abfeebb67015d8f737233865ba32bfc056705")));
    pool_index_map_.insert(std::make_pair(6, common::Encode::HexDecode("da271b7af44f477fa08ae9304ae97567b9f894a6")));
    pool_index_map_.insert(std::make_pair(7, common::Encode::HexDecode("f32df0067e99b878aa5961d5ae0ab76abf6c0215")));
    pool_index_map_.insert(std::make_pair(8, common::Encode::HexDecode("28ecb70c8b9111a42267c5cfdf2b3633c25a8395")));
    pool_index_map_.insert(std::make_pair(9, common::Encode::HexDecode("8b373d3c81291ed6f11d475f6f19148b42c8131a")));
    pool_index_map_.insert(std::make_pair(10, common::Encode::HexDecode("63e3cf9f3f3407680b0c134a4c4b79f9745ade82")));
    pool_index_map_.insert(std::make_pair(11, common::Encode::HexDecode("268f288f2df0d7b3d58763ce138b6ffe0c0aa3d2")));
    pool_index_map_.insert(std::make_pair(12, common::Encode::HexDecode("01e48d9e2b842bde0be5ae000ef1221d3fc310a8")));
    pool_index_map_.insert(std::make_pair(13, common::Encode::HexDecode("9d0d081f1f04365f1c21aee74c974328caea3c8b")));
    pool_index_map_.insert(std::make_pair(14, common::Encode::HexDecode("d5b3e4958fbd5d5ca33ada1512cdc9cc04aef9cb")));
    pool_index_map_.insert(std::make_pair(15, common::Encode::HexDecode("e91e05aca624499858b26afb412a53b45657c1d4")));
    pool_index_map_.insert(std::make_pair(16, common::Encode::HexDecode("fc185ea8b19d76d1217206728b3679dc4f788f9a")));
    pool_index_map_.insert(std::make_pair(17, common::Encode::HexDecode("f13e30793f194ea40094e0f5e788b0f5fe11e2ff")));
    pool_index_map_.insert(std::make_pair(18, common::Encode::HexDecode("314fd64d7a3b44171b5966c33ab5f9f18148df71")));
    pool_index_map_.insert(std::make_pair(19, common::Encode::HexDecode("c94ad207d56423abd5383a294a5df4671c8249fb")));
    pool_index_map_.insert(std::make_pair(20, common::Encode::HexDecode("9cce79480f906e71139326306fc4b31e6cb420e3")));
    pool_index_map_.insert(std::make_pair(21, common::Encode::HexDecode("db457fc9055ca455122c9109676924c7f3ba05d7")));
    pool_index_map_.insert(std::make_pair(22, common::Encode::HexDecode("a2483b14e939126eb2cd2708e8b92e360110ee2d")));
    pool_index_map_.insert(std::make_pair(23, common::Encode::HexDecode("b0def9ff551826b6f37b72cd9d1a54b1dac348f3")));
    pool_index_map_.insert(std::make_pair(24, common::Encode::HexDecode("4353059518410a30d0e8e08993ca06eaf32b9c24")));
    pool_index_map_.insert(std::make_pair(25, common::Encode::HexDecode("cb9feb040a935690762febdcfcc139e70219093a")));
    pool_index_map_.insert(std::make_pair(26, common::Encode::HexDecode("d5f509cc77ecf28f23c79696b507ead450d8e967")));
    pool_index_map_.insert(std::make_pair(27, common::Encode::HexDecode("4c1aa4abbe4d4c185d1db1b87a5b30ab591129d0")));
    pool_index_map_.insert(std::make_pair(28, common::Encode::HexDecode("0577d7ef8e476b20310d74be425238308fb35263")));
    pool_index_map_.insert(std::make_pair(29, common::Encode::HexDecode("2e4f7131f914f3560146e41e5a58b6beb377b2d0")));
    pool_index_map_.insert(std::make_pair(30, common::Encode::HexDecode("6bbd8b7912ac3bf7ed00963f5ddfbbfa911db54f")));
    pool_index_map_.insert(std::make_pair(31, common::Encode::HexDecode("9f18e73ad2c2d6c46b1b6d685e094c8d667edb20")));
    pool_index_map_.insert(std::make_pair(32, common::Encode::HexDecode("c0f882d2a2567584efbfa8ddcf8ea37b63093ea2")));
    pool_index_map_.insert(std::make_pair(33, common::Encode::HexDecode("dc9c1fdb7b22221307073087e21e55d68554bfc2")));
    pool_index_map_.insert(std::make_pair(34, common::Encode::HexDecode("3acdea41155b047c1350b5c413ffd9444931dafb")));
    pool_index_map_.insert(std::make_pair(35, common::Encode::HexDecode("71e355d460e27e05010230661b7dcf0c5ccb990d")));
    pool_index_map_.insert(std::make_pair(36, common::Encode::HexDecode("0661839c1ef0c65f5d8c38e90d7ff3275313ee56")));
    pool_index_map_.insert(std::make_pair(37, common::Encode::HexDecode("0c4b71a0d40691d133670f179e564436cac8e9d8")));
    pool_index_map_.insert(std::make_pair(38, common::Encode::HexDecode("cab76d0c46567a29680337ecec1a23594a7d3f5d")));
    pool_index_map_.insert(std::make_pair(39, common::Encode::HexDecode("5cc3df57e59fd820b97786ded4bd7e91aa36aa34")));
    pool_index_map_.insert(std::make_pair(40, common::Encode::HexDecode("97f12b1923a16e098562c4aaef073360a8a6f34f")));
    pool_index_map_.insert(std::make_pair(41, common::Encode::HexDecode("fb6b5d5922df6daea845dfa7b101a24ff9b2c061")));
    pool_index_map_.insert(std::make_pair(42, common::Encode::HexDecode("295af681b9291cd83579ca084d09931ce0fb12b3")));
    pool_index_map_.insert(std::make_pair(43, common::Encode::HexDecode("b8756fdae290caedff091d983ef775148f66dc0d")));
    pool_index_map_.insert(std::make_pair(44, common::Encode::HexDecode("1af234ca1142a5c2f89fc3d617c0d934517d6836")));
    pool_index_map_.insert(std::make_pair(45, common::Encode::HexDecode("4c9a2e422c095fa5229b16e7e83734e083dfe501")));
    pool_index_map_.insert(std::make_pair(46, common::Encode::HexDecode("8ff64c185797e477cf39db3e196339aba9414d3c")));
    pool_index_map_.insert(std::make_pair(47, common::Encode::HexDecode("bf8e603cb63595f4a9e59227a1cc1665ef70244a")));
    pool_index_map_.insert(std::make_pair(48, common::Encode::HexDecode("3af012ffb02273f6587ecea705d1fd299a707f07")));
    pool_index_map_.insert(std::make_pair(49, common::Encode::HexDecode("c48f4958b2c8eaca225aa66805c27c1cfc4cb0d6")));
    pool_index_map_.insert(std::make_pair(50, common::Encode::HexDecode("17196ab8c64b55657c1dd2de9482a6d17d9bfcac")));
    pool_index_map_.insert(std::make_pair(51, common::Encode::HexDecode("0d001ca82adc6b698accc29eeb7f4812cc9b89b4")));
    pool_index_map_.insert(std::make_pair(52, common::Encode::HexDecode("0557e09168aeeda7ca074e4b0353a702ee836044")));
    pool_index_map_.insert(std::make_pair(53, common::Encode::HexDecode("21319eb24c1332d39cb2f8273fa8154aa94584ea")));
    pool_index_map_.insert(std::make_pair(54, common::Encode::HexDecode("88c03a4a813700779f34bf06b6c582f1a76a9819")));
    pool_index_map_.insert(std::make_pair(55, common::Encode::HexDecode("1cc705cf80d38525f1ae19b1370e9cc2da167865")));
    pool_index_map_.insert(std::make_pair(56, common::Encode::HexDecode("51f8fa78ab1d13c4fa72ecba181d58a65c677b99")));
    pool_index_map_.insert(std::make_pair(57, common::Encode::HexDecode("18e73f34fb72d2a9ca2c94936db663a1a17302ee")));
    pool_index_map_.insert(std::make_pair(58, common::Encode::HexDecode("cc129fd9ce1b6205da7f6093391e78e444a8088e")));
    pool_index_map_.insert(std::make_pair(59, common::Encode::HexDecode("eeb8df10557c3ba4125194b96a562ca4689bbd5d")));
    pool_index_map_.insert(std::make_pair(60, common::Encode::HexDecode("56266255378d0dc09b2d693a397358981a7b02f5")));
    pool_index_map_.insert(std::make_pair(61, common::Encode::HexDecode("c9fdadc4c718d5013ffb0b143b7bb856f13b91b0")));
    pool_index_map_.insert(std::make_pair(62, common::Encode::HexDecode("16b95c73e37c00a01dff8ece45ab29ca2e3be5bc")));
    pool_index_map_.insert(std::make_pair(63, common::Encode::HexDecode("6ca9f26dc4072505d30cdd42af409c39e1d97ab0")));
    pool_index_map_.insert(std::make_pair(64, common::Encode::HexDecode("f9fe9c4fe58d406cdf0c18f1ace1fca82f28ad06")));
    pool_index_map_.insert(std::make_pair(65, common::Encode::HexDecode("41e289872ff551f27bac326e30251fa5b2cbc300")));
    pool_index_map_.insert(std::make_pair(66, common::Encode::HexDecode("8fe736d9bfa7e7a982b7430eff284ce3ffb35b53")));
    pool_index_map_.insert(std::make_pair(67, common::Encode::HexDecode("412c1f5b8d560af246e0b3499e95530682e5249d")));
    pool_index_map_.insert(std::make_pair(68, common::Encode::HexDecode("fa36a774160cc729760113e856495b563e56f9e9")));
    pool_index_map_.insert(std::make_pair(69, common::Encode::HexDecode("1d642b27a1504258a1b34fb2bb9dbdbe3449de6d")));
    pool_index_map_.insert(std::make_pair(70, common::Encode::HexDecode("96114c421dced031205bb5829b5685fb62f3cc1f")));
    pool_index_map_.insert(std::make_pair(71, common::Encode::HexDecode("2bc3cba8a358620336a0af64655bf503794ac845")));
    pool_index_map_.insert(std::make_pair(72, common::Encode::HexDecode("b18e1502695663878264e9082e70272d95661034")));
    pool_index_map_.insert(std::make_pair(73, common::Encode::HexDecode("60fc3ec9a7d80281032a915fe953556158183b89")));
    pool_index_map_.insert(std::make_pair(74, common::Encode::HexDecode("eedb4ae5e30e22e5053e170e4c672cdffbb71bb2")));
    pool_index_map_.insert(std::make_pair(75, common::Encode::HexDecode("81846f9531493eb27298c16928711836439d83c6")));
    pool_index_map_.insert(std::make_pair(76, common::Encode::HexDecode("7cc086a9f8d91914bcd6d24ee5b64634e655e1c4")));
    pool_index_map_.insert(std::make_pair(77, common::Encode::HexDecode("c1245932486886acf51275b315ccd12cf2d9b464")));
    pool_index_map_.insert(std::make_pair(78, common::Encode::HexDecode("c99841e564acf4d999e2c2f9327f5639ea88b734")));
    pool_index_map_.insert(std::make_pair(79, common::Encode::HexDecode("cb1051a6602491a5472853441d59693f4eb9237c")));
    pool_index_map_.insert(std::make_pair(80, common::Encode::HexDecode("98735b1d1017cf703433938f1d62572c1ee98e07")));
    pool_index_map_.insert(std::make_pair(81, common::Encode::HexDecode("f9f25857a611a7067375df8f09b20a5083a940db")));
    pool_index_map_.insert(std::make_pair(82, common::Encode::HexDecode("483252e40e7083ae19bbde68c16f70da7723159e")));
    pool_index_map_.insert(std::make_pair(83, common::Encode::HexDecode("6f84cd4cf8b632d8654bdbe5fba8029b0b07b2a6")));
    pool_index_map_.insert(std::make_pair(84, common::Encode::HexDecode("7b9c274eae20c1eebbf12b042ed84a2048d09c44")));
    pool_index_map_.insert(std::make_pair(85, common::Encode::HexDecode("26eb8364c4e593d77d093a335ba0153f72c8ab54")));
    pool_index_map_.insert(std::make_pair(86, common::Encode::HexDecode("34e161294cbcc5f40cc23a2815e6dfe4ea228365")));
    pool_index_map_.insert(std::make_pair(87, common::Encode::HexDecode("0a40d0d0437b2aacd4c31a753c8d370fd4b90880")));
    pool_index_map_.insert(std::make_pair(88, common::Encode::HexDecode("7c548ae84e925f47322fbd1cf9781f7a8880b985")));
    pool_index_map_.insert(std::make_pair(89, common::Encode::HexDecode("c5d28ac87de63338008f6a377be84009060b3da8")));
    pool_index_map_.insert(std::make_pair(90, common::Encode::HexDecode("39e50fbe1e1a16f7780628d5ddd5cfa960c85419")));
    pool_index_map_.insert(std::make_pair(91, common::Encode::HexDecode("b0a47d84dcd071af3b71474519ecefb859bfd31c")));
    pool_index_map_.insert(std::make_pair(92, common::Encode::HexDecode("f6499fd02a058ea406ac675b17201fad631a3a72")));
    pool_index_map_.insert(std::make_pair(93, common::Encode::HexDecode("49623b548f68d87cbc7d28d5f43f0b4f024f0fff")));
    pool_index_map_.insert(std::make_pair(94, common::Encode::HexDecode("c4bff657af6c13089acba86a9972123cc7ca9ce5")));
    pool_index_map_.insert(std::make_pair(95, common::Encode::HexDecode("ce8a90aa4ada14cc4e5be16b42bdb510f2a4be6a")));
    pool_index_map_.insert(std::make_pair(96, common::Encode::HexDecode("7614e840fc88d7081ecfd03eaa0f09369d0ff9b1")));
    pool_index_map_.insert(std::make_pair(97, common::Encode::HexDecode("b1e2ceca48dbdc711feca6815743e9b266798581")));
    pool_index_map_.insert(std::make_pair(98, common::Encode::HexDecode("c513ba24d79f6adc5060caebc9267663457f74c2")));
    pool_index_map_.insert(std::make_pair(99, common::Encode::HexDecode("b4a149ae07b201aaf1eae97d27d7d7045b9953e8")));
    pool_index_map_.insert(std::make_pair(100, common::Encode::HexDecode("88a1badd3ba1b8f45b71c957898589c21630d298")));
    pool_index_map_.insert(std::make_pair(101, common::Encode::HexDecode("2e7070934101e5b1ff739b6a2491e5c47db6f9e7")));
    pool_index_map_.insert(std::make_pair(102, common::Encode::HexDecode("34b7abc72fc41090c2c61e310c9164293db529ca")));
    pool_index_map_.insert(std::make_pair(103, common::Encode::HexDecode("18d503bf466707523ef2abbf464cd71d9a984509")));
    pool_index_map_.insert(std::make_pair(104, common::Encode::HexDecode("bb2996e29d3083c3bf2a7ed5e3f194f24403c4e8")));
    pool_index_map_.insert(std::make_pair(105, common::Encode::HexDecode("0a25e9586c679bfe795412f544b9a4525641a5d3")));
    pool_index_map_.insert(std::make_pair(106, common::Encode::HexDecode("1bdf2d324df346ac85dcce2c1e560dcfeffdcb64")));
    pool_index_map_.insert(std::make_pair(107, common::Encode::HexDecode("d6179b5a6bba6481ca93ac6d4cadc1c803802aad")));
    pool_index_map_.insert(std::make_pair(108, common::Encode::HexDecode("1dca9ca726734683bdaace8f623aac7ec08b4115")));
    pool_index_map_.insert(std::make_pair(109, common::Encode::HexDecode("ddf19b705dc8e1ea71358d84f57998c03ede5952")));
    pool_index_map_.insert(std::make_pair(110, common::Encode::HexDecode("c48e29dd1a43e009cd47662d114a410db4926a63")));
    pool_index_map_.insert(std::make_pair(111, common::Encode::HexDecode("6bfaa13ed4914a933a5762a81ab12d5c6cd843d9")));
    pool_index_map_.insert(std::make_pair(112, common::Encode::HexDecode("9ccde333aa03c5f2260eeb77a2d0760cf43e7942")));
    pool_index_map_.insert(std::make_pair(113, common::Encode::HexDecode("df9222690b2e29910dd887c0a0c8d178203f218e")));
    pool_index_map_.insert(std::make_pair(114, common::Encode::HexDecode("abea2a512b51cb9f9436f182fcc879c3c76a24cc")));
    pool_index_map_.insert(std::make_pair(115, common::Encode::HexDecode("0f63f56c19c4d44716f47596db479e8ca4c38a22")));
    pool_index_map_.insert(std::make_pair(116, common::Encode::HexDecode("c382eb99ab1f92018cbe3f205765b5d0a9c596d0")));
    pool_index_map_.insert(std::make_pair(117, common::Encode::HexDecode("8b9f5ccb8cd2ed0345287cff5613e2dc9a30aae7")));
    pool_index_map_.insert(std::make_pair(118, common::Encode::HexDecode("77fb06faad9b2cb04b30edbec5ac00754f0149f9")));
    pool_index_map_.insert(std::make_pair(119, common::Encode::HexDecode("f334c04f381eab86a951140549551cfe0cd90701")));
    pool_index_map_.insert(std::make_pair(120, common::Encode::HexDecode("29da6e9b9b2b5588d81de9254d02d19d55795f05")));
    pool_index_map_.insert(std::make_pair(121, common::Encode::HexDecode("2842ffea71637aa87f61bb1bbd71180fbd134bf7")));
    pool_index_map_.insert(std::make_pair(122, common::Encode::HexDecode("8022e6a0823e6a45f47efbd0be6e194de4a04573")));
    pool_index_map_.insert(std::make_pair(123, common::Encode::HexDecode("775f175412967c61318327a1a7db9119e4b33333")));
    pool_index_map_.insert(std::make_pair(124, common::Encode::HexDecode("aaec0dc5c881ede4d507db2b2154de8e159a54d9")));
    pool_index_map_.insert(std::make_pair(125, common::Encode::HexDecode("d638fb635132dcc294805c30ec5e1045f7558c5f")));
    pool_index_map_.insert(std::make_pair(126, common::Encode::HexDecode("69621c2fe505da8fbaedeeed3125c71c9756c503")));
    pool_index_map_.insert(std::make_pair(127, common::Encode::HexDecode("177a7ca644c3ea544067cc54798fac84dbb3939f")));
    pool_index_map_.insert(std::make_pair(128, common::Encode::HexDecode("786445b255db38064cb73a22c9d0659f23b61b56")));
    pool_index_map_.insert(std::make_pair(129, common::Encode::HexDecode("fb263959618874d2ba28f7d966ec6ec6c7a34a30")));
    pool_index_map_.insert(std::make_pair(130, common::Encode::HexDecode("c65c4d412782960acf6bcbb7d52b9725c0faee1f")));
    pool_index_map_.insert(std::make_pair(131, common::Encode::HexDecode("5dd53bb0c43ddcafc73d280273629e1f63e8e333")));
    pool_index_map_.insert(std::make_pair(132, common::Encode::HexDecode("aff2a88df88e5e28b113470b1f8d97cccc56cd63")));
    pool_index_map_.insert(std::make_pair(133, common::Encode::HexDecode("22983d7dbc7b718493fc2173cc7866a3d451df46")));
    pool_index_map_.insert(std::make_pair(134, common::Encode::HexDecode("d152561251741f79d2403e25312a2972a2e9d9d5")));
    pool_index_map_.insert(std::make_pair(135, common::Encode::HexDecode("40d0f81dd786063baeb7e92b1954958db5771167")));
    pool_index_map_.insert(std::make_pair(136, common::Encode::HexDecode("f7e59d52f3c1603281ed1bed9bc109efd7a419f1")));
    pool_index_map_.insert(std::make_pair(137, common::Encode::HexDecode("c34f2ddc5d31319f28cef772c39a05cf4d4432de")));
    pool_index_map_.insert(std::make_pair(138, common::Encode::HexDecode("eefb2a5dd23c53c87d9dc519da330172992651e7")));
    pool_index_map_.insert(std::make_pair(139, common::Encode::HexDecode("5aaab9acc94e319b731363f4007e0927bf1f69e3")));
    pool_index_map_.insert(std::make_pair(140, common::Encode::HexDecode("8a67b1aa76ab51fd6d5ea8f9e8770964e626cdc0")));
    pool_index_map_.insert(std::make_pair(141, common::Encode::HexDecode("4549a94a23afc279a760980d4fcaf889937861ef")));
    pool_index_map_.insert(std::make_pair(142, common::Encode::HexDecode("49a797bdb331ff78217e263dd4b1439726e8b59a")));
    pool_index_map_.insert(std::make_pair(143, common::Encode::HexDecode("8193ee50a76382b1b124bc494adca120113aa48d")));
    pool_index_map_.insert(std::make_pair(144, common::Encode::HexDecode("853e6f118502a684005731d6eb174e0b9fc6e859")));
    pool_index_map_.insert(std::make_pair(145, common::Encode::HexDecode("e7aeceec255677d5dd3b59a91e23a4ae3a422b51")));
    pool_index_map_.insert(std::make_pair(146, common::Encode::HexDecode("596ba8221c1c821ea181173fb19539eb6283336f")));
    pool_index_map_.insert(std::make_pair(147, common::Encode::HexDecode("ea21434c2e8f44f8f3f1159808377abfd727bf20")));
    pool_index_map_.insert(std::make_pair(148, common::Encode::HexDecode("02e9c3d905d00f356f7fc226fed2a317e64d2c93")));
    pool_index_map_.insert(std::make_pair(149, common::Encode::HexDecode("c1b70e85ce50636f663bec5227a90c3375e54575")));
    pool_index_map_.insert(std::make_pair(150, common::Encode::HexDecode("9b653edb242e4e7f9ee3739c58fb2fcdc99b4be4")));
    pool_index_map_.insert(std::make_pair(151, common::Encode::HexDecode("1610974db88016172cfa0030601be0e71c543cbe")));
    pool_index_map_.insert(std::make_pair(152, common::Encode::HexDecode("77fbdb4ebbf5006fdeb0fe03774d684010b72c49")));
    pool_index_map_.insert(std::make_pair(153, common::Encode::HexDecode("3b232f8c6070fb536ae9ec562b056cfafb892a04")));
    pool_index_map_.insert(std::make_pair(154, common::Encode::HexDecode("a37614f3b799d6235b0fcaabd7661d54dfef2afb")));
    pool_index_map_.insert(std::make_pair(155, common::Encode::HexDecode("7124fec8a86892e5551bd8e6bb19f9195611dadd")));
    pool_index_map_.insert(std::make_pair(156, common::Encode::HexDecode("62c0ffbbcf6fe1111f8086773e2cccd8fd467689")));
    pool_index_map_.insert(std::make_pair(157, common::Encode::HexDecode("f7218e22c727ff546513a757cfba65f5856c65f8")));
    pool_index_map_.insert(std::make_pair(158, common::Encode::HexDecode("128ca33cc34e5b879ed25f267386fdf13f07cb14")));
    pool_index_map_.insert(std::make_pair(159, common::Encode::HexDecode("c5ca92ec2447eeebe046185b7da379a78f525882")));
    pool_index_map_.insert(std::make_pair(160, common::Encode::HexDecode("402d6113a6c2cbefe0cf4c7838118f600092e037")));
    pool_index_map_.insert(std::make_pair(161, common::Encode::HexDecode("c942d2b8a1438af1014c6439f51915b93f17df76")));
    pool_index_map_.insert(std::make_pair(162, common::Encode::HexDecode("02de1d19b3d3da3ec2c5b871c394a217da1b21d6")));
    pool_index_map_.insert(std::make_pair(163, common::Encode::HexDecode("9c6c283e147ae83e13f9a04259450594ea8ebbae")));
    pool_index_map_.insert(std::make_pair(164, common::Encode::HexDecode("c01da5e07ee0f2e583688877843cc9f49fb0322a")));
    pool_index_map_.insert(std::make_pair(165, common::Encode::HexDecode("34ba028121e3b1ecf5c128908d0eac7ca2e33d85")));
    pool_index_map_.insert(std::make_pair(166, common::Encode::HexDecode("36dbd2ecd1cf6c5b214f923c1931345de347e0e9")));
    pool_index_map_.insert(std::make_pair(167, common::Encode::HexDecode("06ca2a6614f9228b210d51642bb21c28cfdf6fdf")));
    pool_index_map_.insert(std::make_pair(168, common::Encode::HexDecode("4711665c910f292c9bad6e60ca0696e65dc4b917")));
    pool_index_map_.insert(std::make_pair(169, common::Encode::HexDecode("db135e683a17d6c9ffef5ffd0f55ceacb59130cb")));
    pool_index_map_.insert(std::make_pair(170, common::Encode::HexDecode("6cf884eed83adef1f3954d17fc355f7120f43f10")));
    pool_index_map_.insert(std::make_pair(171, common::Encode::HexDecode("06e22cc72eac9882040d94e783936351ef1dc545")));
    pool_index_map_.insert(std::make_pair(172, common::Encode::HexDecode("0039bfef9825ac25b0083c74f450006f875eb1ba")));
    pool_index_map_.insert(std::make_pair(173, common::Encode::HexDecode("8e6e52068d4851ce7a85e0b7058840ec9a6dec13")));
    pool_index_map_.insert(std::make_pair(174, common::Encode::HexDecode("8f7428a3ca44d9096d348a5014a58803e3e8de88")));
    pool_index_map_.insert(std::make_pair(175, common::Encode::HexDecode("6f574ea9c0e5f38a02e716229f7836833c3b7d21")));
    pool_index_map_.insert(std::make_pair(176, common::Encode::HexDecode("bd4a82ba977175af733050cffbd2886f26e5527a")));
    pool_index_map_.insert(std::make_pair(177, common::Encode::HexDecode("73b277274289a83787ba123a088947e68511d78b")));
    pool_index_map_.insert(std::make_pair(178, common::Encode::HexDecode("240ed7069391e3b91e55dcc9ff6bdea7845b8b77")));
    pool_index_map_.insert(std::make_pair(179, common::Encode::HexDecode("85a453610614cbf2b0104006a9e764653f54d971")));
    pool_index_map_.insert(std::make_pair(180, common::Encode::HexDecode("434068c663b0ec32bbc3311b8d5a2b024c481625")));
    pool_index_map_.insert(std::make_pair(181, common::Encode::HexDecode("965bb704c0daafee068947f8cec56d4ab592380f")));
    pool_index_map_.insert(std::make_pair(182, common::Encode::HexDecode("ca31e75922f8458574bd329dc3e2aa7cd4a9156a")));
    pool_index_map_.insert(std::make_pair(183, common::Encode::HexDecode("b14883c5aae402b59f599e988fb0c9224fac27b7")));
    pool_index_map_.insert(std::make_pair(184, common::Encode::HexDecode("ae35f4eda893df658920dc233f504f8f2c181c06")));
    pool_index_map_.insert(std::make_pair(185, common::Encode::HexDecode("811d395a6ea0d4b1195f9ef18f9badb93ba2513e")));
    pool_index_map_.insert(std::make_pair(186, common::Encode::HexDecode("33f6e4fab1f28fec4648d238eb2c2209a320bb9d")));
    pool_index_map_.insert(std::make_pair(187, common::Encode::HexDecode("3a9c0ac8fd6c210aab6fc400dd881a53bf121122")));
    pool_index_map_.insert(std::make_pair(188, common::Encode::HexDecode("ac247a3ea175a16cd1b92ca97f47370f5dc0fe62")));
    pool_index_map_.insert(std::make_pair(189, common::Encode::HexDecode("9222f11e8c29dd6bc7fc2faa15f680781aa73847")));
    pool_index_map_.insert(std::make_pair(190, common::Encode::HexDecode("408af53c4827906897c023435064b288d1565a98")));
    pool_index_map_.insert(std::make_pair(191, common::Encode::HexDecode("caa8549db5ec092578e505355da4ff7fa56b11f1")));
    pool_index_map_.insert(std::make_pair(192, common::Encode::HexDecode("07d353101c2d33137234ca3cd9a713fe91f58b34")));
    pool_index_map_.insert(std::make_pair(193, common::Encode::HexDecode("bee246fe942f1b4ddf9e8c0e7d484faecc12b29d")));
    pool_index_map_.insert(std::make_pair(194, common::Encode::HexDecode("11dce9736372cc861005a37f02105a0c8c193898")));
    pool_index_map_.insert(std::make_pair(195, common::Encode::HexDecode("112fa59c5748ebfda3b47848ce305943d56ab313")));
    pool_index_map_.insert(std::make_pair(196, common::Encode::HexDecode("10ade4df47a6eb0b8cf6f138667220c36549c1b0")));
    pool_index_map_.insert(std::make_pair(197, common::Encode::HexDecode("a04d73dc1d8bd5f14992607c042690e14eb79dc4")));
    pool_index_map_.insert(std::make_pair(198, common::Encode::HexDecode("a12cda4d35c889e59e75d9faa45e8c768443b075")));
    pool_index_map_.insert(std::make_pair(199, common::Encode::HexDecode("b8964f3acb165c007ef01cf259c790ad3bf29385")));
    pool_index_map_.insert(std::make_pair(200, common::Encode::HexDecode("89485eacce35c604262cac15b583db05410b526b")));
    pool_index_map_.insert(std::make_pair(201, common::Encode::HexDecode("db2d2e9aa356094e36409524eff906654cc7674b")));
    pool_index_map_.insert(std::make_pair(202, common::Encode::HexDecode("93b39ce310306acf0e880cda0a46449c673bf9c6")));
    pool_index_map_.insert(std::make_pair(203, common::Encode::HexDecode("355caacbee3e2d19cccbdb8632a5a2e63b597e2f")));
    pool_index_map_.insert(std::make_pair(204, common::Encode::HexDecode("e16b17633fe1938ea30abcdf51f325d5dee75acd")));
    pool_index_map_.insert(std::make_pair(205, common::Encode::HexDecode("636ef64184312bda1cf52177dd66ce5fc112947e")));
    pool_index_map_.insert(std::make_pair(206, common::Encode::HexDecode("534feadbe54d8ca5598f9828c642d65b3ffa9065")));
    pool_index_map_.insert(std::make_pair(207, common::Encode::HexDecode("a140548c2dc33ad361cad8a8f37177abf325285f")));
    pool_index_map_.insert(std::make_pair(208, common::Encode::HexDecode("6eac201fda4f04332d394cb1c38a7cd55c8cabc1")));
    pool_index_map_.insert(std::make_pair(209, common::Encode::HexDecode("2627e2f7f2f2e6dd51ba6b685e0a0ddb8168bd05")));
    pool_index_map_.insert(std::make_pair(210, common::Encode::HexDecode("b1a2d3053558587ee7e95f1fd90dced82e171d68")));
    pool_index_map_.insert(std::make_pair(211, common::Encode::HexDecode("4bbd222fecf7759de13ab2f7a03aa2bdd4da11aa")));
    pool_index_map_.insert(std::make_pair(212, common::Encode::HexDecode("d88854ed44a171157fcd5219840f278b1222e26a")));
    pool_index_map_.insert(std::make_pair(213, common::Encode::HexDecode("f6fc6cc0ddee55700fef374f221422edd30d1afb")));
    pool_index_map_.insert(std::make_pair(214, common::Encode::HexDecode("88f45017e79a3b95d7840b050beceaffdb4b32ad")));
    pool_index_map_.insert(std::make_pair(215, common::Encode::HexDecode("5c50d66a70c26afd6528ea648745ced3a02e414a")));
    pool_index_map_.insert(std::make_pair(216, common::Encode::HexDecode("63f7ad696a38d902f2531ff7d92971411ba34073")));
    pool_index_map_.insert(std::make_pair(217, common::Encode::HexDecode("e80c5a387546d7142149d1d8706527c3e2d5a037")));
    pool_index_map_.insert(std::make_pair(218, common::Encode::HexDecode("5499db258ba48e75e5648e158f438664130b26f5")));
    pool_index_map_.insert(std::make_pair(219, common::Encode::HexDecode("6ad3e88665f4afbefc00768b0be16af8f7fa1784")));
    pool_index_map_.insert(std::make_pair(220, common::Encode::HexDecode("c0651770c750f9116a7fb437b3827131eb4bb571")));
    pool_index_map_.insert(std::make_pair(221, common::Encode::HexDecode("9e87cf3e767894bd188141703a9c1b43027d81f5")));
    pool_index_map_.insert(std::make_pair(222, common::Encode::HexDecode("ef2485cd243322424593e35c8790dfbd0d09fc28")));
    pool_index_map_.insert(std::make_pair(223, common::Encode::HexDecode("2a0e8aca79489e68cae5a417f53ed9a500825bb9")));
    pool_index_map_.insert(std::make_pair(224, common::Encode::HexDecode("9c5026385a482097684e996e325a9ba4d9c2e009")));
    pool_index_map_.insert(std::make_pair(225, common::Encode::HexDecode("c81c89c1e398d0e2a3584300b14da0a43f549932")));
    pool_index_map_.insert(std::make_pair(226, common::Encode::HexDecode("7ec4b16ddb26defc103bab802c08131ad2a27df7")));
    pool_index_map_.insert(std::make_pair(227, common::Encode::HexDecode("f8954ed35ed43b1d02d21ac656740f3aa0ef17a3")));
    pool_index_map_.insert(std::make_pair(228, common::Encode::HexDecode("763278d6b880261be8db9b078bbd337c0f5b87b0")));
    pool_index_map_.insert(std::make_pair(229, common::Encode::HexDecode("c21ee5b283b9dfbbd7b0da31e04cebe49f1d000a")));
    pool_index_map_.insert(std::make_pair(230, common::Encode::HexDecode("c7b47259d3b475f98871ab86b08663e92099e2a3")));
    pool_index_map_.insert(std::make_pair(231, common::Encode::HexDecode("351cd80300baed5a57d325cb9e322a0ff64870a5")));
    pool_index_map_.insert(std::make_pair(232, common::Encode::HexDecode("49cdb2ec8d0c8b86cbb95619eac64b90555d578a")));
    pool_index_map_.insert(std::make_pair(233, common::Encode::HexDecode("8acb15f19e45177de4576f3eca794d9bd3bef4fc")));
    pool_index_map_.insert(std::make_pair(234, common::Encode::HexDecode("25975280333028885c9abee69eb11a4b186f6cca")));
    pool_index_map_.insert(std::make_pair(235, common::Encode::HexDecode("ba8dd0b250dcdf295b05b142fabf520662ba979a")));
    pool_index_map_.insert(std::make_pair(236, common::Encode::HexDecode("239bcf9b11e97daf7cba2e3a4334a1fc29a4e988")));
    pool_index_map_.insert(std::make_pair(237, common::Encode::HexDecode("bfde88be488d920ea61dc43edd5aeaf1ba348985")));
    pool_index_map_.insert(std::make_pair(238, common::Encode::HexDecode("c8b02c6b0cf4789284d99f87872ac6c37a3ceb3b")));
    pool_index_map_.insert(std::make_pair(239, common::Encode::HexDecode("bdc88e480aa79d3078a9167fde73a818ba3d47ba")));
    pool_index_map_.insert(std::make_pair(240, common::Encode::HexDecode("fc64afa818e99fda8d60b94a644b7d75b86d9d0b")));
    pool_index_map_.insert(std::make_pair(241, common::Encode::HexDecode("c7b921164133cd500517b5644182cb0c5ea3d3b4")));
    pool_index_map_.insert(std::make_pair(242, common::Encode::HexDecode("6b61d275f5aaa943899253f3a4f00498e80a13f2")));
    pool_index_map_.insert(std::make_pair(243, common::Encode::HexDecode("90fc10c5403f79c3020510845914bd8495220b71")));
    pool_index_map_.insert(std::make_pair(244, common::Encode::HexDecode("ab4c422cf06380dff6d2d103fff03a486a300dd6")));
    pool_index_map_.insert(std::make_pair(245, common::Encode::HexDecode("f375c82e0f47b9e99831f0c62c5c5fc8176184b3")));
    pool_index_map_.insert(std::make_pair(246, common::Encode::HexDecode("74538751a76f355558aab13d5ef9bc1b2c685502")));
    pool_index_map_.insert(std::make_pair(247, common::Encode::HexDecode("d38a79ee41532f004d30ca66d2b90eb9c94274a2")));
    pool_index_map_.insert(std::make_pair(248, common::Encode::HexDecode("8c7639f61c307e869ef7a846ef790106dc81519e")));
    pool_index_map_.insert(std::make_pair(249, common::Encode::HexDecode("6e3eb5a3afa982a0969d93979d52c77e90d2f5fb")));
    pool_index_map_.insert(std::make_pair(250, common::Encode::HexDecode("555999112d573a1e34c5ec5825ff607c312764ad")));
    pool_index_map_.insert(std::make_pair(251, common::Encode::HexDecode("67858fa20809fc86b48984a40d0776b30363c5a0")));
    pool_index_map_.insert(std::make_pair(252, common::Encode::HexDecode("ad6beabde34572510957b2090c76ce8e96cad4d0")));
    pool_index_map_.insert(std::make_pair(253, common::Encode::HexDecode("459cfa2736b187edf318c0679dea183abcaa2fac")));
    pool_index_map_.insert(std::make_pair(254, common::Encode::HexDecode("ac04be3783198e515cbd352bb29dc34fc035f282")));
    pool_index_map_.insert(std::make_pair(255, common::Encode::HexDecode("8bba568dc5f77756982f728afc2b154a5a49b1cb")));
}

void GenesisBlockInit::GenerateRootAccounts() {
    root_account_with_pool_index_map_.insert(std::make_pair(0, common::Encode::HexDecode("34ee872ca038b7c8fc8245b137b3f3f54355ce17")));
    root_account_with_pool_index_map_.insert(std::make_pair(1, common::Encode::HexDecode("b6deb5d8f05904541bd201600f9142ac4fac713f")));
    root_account_with_pool_index_map_.insert(std::make_pair(2, common::Encode::HexDecode("46f6c0783cd3d4717ff7edc31cef4345ccc3f3f5")));
    root_account_with_pool_index_map_.insert(std::make_pair(3, common::Encode::HexDecode("9a6f7d37a588a5c36349b8cac96b42732efa3e48")));
    root_account_with_pool_index_map_.insert(std::make_pair(4, common::Encode::HexDecode("c8f5aa99c480befb9153319c53ece96e436c47a4")));
    root_account_with_pool_index_map_.insert(std::make_pair(5, common::Encode::HexDecode("79d0376cfb61be21cb2fcb71327c76289f83d4e6")));
    root_account_with_pool_index_map_.insert(std::make_pair(6, common::Encode::HexDecode("ffa80466f4288a746ddacca059ce8387c177d291")));
    root_account_with_pool_index_map_.insert(std::make_pair(7, common::Encode::HexDecode("8b27e68bebef1854837dbab778cd3c90c799f84e")));
    root_account_with_pool_index_map_.insert(std::make_pair(8, common::Encode::HexDecode("5579c13251c251c0bbbc1de72de6dda9adc13691")));
    root_account_with_pool_index_map_.insert(std::make_pair(9, common::Encode::HexDecode("3de466ef7b63ba5acb9206a9cf28b023afd3bcf2")));
    root_account_with_pool_index_map_.insert(std::make_pair(10, common::Encode::HexDecode("78d067c173ff30db98014c157e21d03cadf5f46e")));
    root_account_with_pool_index_map_.insert(std::make_pair(11, common::Encode::HexDecode("c4feec39ee85e479275dbce11b8c9d2f712595fa")));
    root_account_with_pool_index_map_.insert(std::make_pair(12, common::Encode::HexDecode("24a2b740dc9ba9c7720179606b174cc9cd46d0f7")));
    root_account_with_pool_index_map_.insert(std::make_pair(13, common::Encode::HexDecode("428f33fe4332f17ed2cc7878fea697b798008f84")));
    root_account_with_pool_index_map_.insert(std::make_pair(14, common::Encode::HexDecode("0703e586d4593b64ceb562a90e909917a5ebacc4")));
    root_account_with_pool_index_map_.insert(std::make_pair(15, common::Encode::HexDecode("741c0529ce598cd6ab8ffc3c5fa0b10cd90f2a95")));
    root_account_with_pool_index_map_.insert(std::make_pair(16, common::Encode::HexDecode("8fa092f1e7d2243b9a4b7fc59a3f5fe1ffe739b0")));
    root_account_with_pool_index_map_.insert(std::make_pair(17, common::Encode::HexDecode("0831190a801210deb7726c9c88d7ec2dd443d370")));
    root_account_with_pool_index_map_.insert(std::make_pair(18, common::Encode::HexDecode("8a34cdeaddcb42f7357b23055b3cf256a64f5a99")));
    root_account_with_pool_index_map_.insert(std::make_pair(19, common::Encode::HexDecode("94b13f03ba6cf0914ec96ec617dfe9381cc83032")));
    root_account_with_pool_index_map_.insert(std::make_pair(20, common::Encode::HexDecode("b361a64853befa5a3be008a1ad5ba4e1031a3e6c")));
    root_account_with_pool_index_map_.insert(std::make_pair(21, common::Encode::HexDecode("0953dbcbffa8a4a8764936dc16b62b104650ad87")));
    root_account_with_pool_index_map_.insert(std::make_pair(22, common::Encode::HexDecode("69c1c3a80e9f5df12cad768ddab9d44df68d6a56")));
    root_account_with_pool_index_map_.insert(std::make_pair(23, common::Encode::HexDecode("8554361c965e4d608e5e08d73a333be42222e6b2")));
    root_account_with_pool_index_map_.insert(std::make_pair(24, common::Encode::HexDecode("2a3530683cd719006d57c2ecb130b1c1e20ed5c9")));
    root_account_with_pool_index_map_.insert(std::make_pair(25, common::Encode::HexDecode("d2a716a2c35e50f1c7e1cba925c276b69ccb34aa")));
    root_account_with_pool_index_map_.insert(std::make_pair(26, common::Encode::HexDecode("9f4d1c0b804ef7b70ebcc9476500e9d5c0db79ca")));
    root_account_with_pool_index_map_.insert(std::make_pair(27, common::Encode::HexDecode("9c34bb21b1005313d4f4c40be201df5044e05576")));
    root_account_with_pool_index_map_.insert(std::make_pair(28, common::Encode::HexDecode("ecd8d150125e61f8396d9b58093dcde5872a05bd")));
    root_account_with_pool_index_map_.insert(std::make_pair(29, common::Encode::HexDecode("9f3b395acb1a90916bf637ff52f5193180dc849e")));
    root_account_with_pool_index_map_.insert(std::make_pair(30, common::Encode::HexDecode("c322ab5789f5737b87fad9179344c4ea2c59835f")));
    root_account_with_pool_index_map_.insert(std::make_pair(31, common::Encode::HexDecode("d03dab8b2422f2dd007fe2030ece2fb0a6b7119f")));
    root_account_with_pool_index_map_.insert(std::make_pair(32, common::Encode::HexDecode("2c55bb7ca36f07760c244b0a9a02a127db52d4a4")));
    root_account_with_pool_index_map_.insert(std::make_pair(33, common::Encode::HexDecode("dabe97dc26bf7c5e938640a6f8198ba6eaff59f8")));
    root_account_with_pool_index_map_.insert(std::make_pair(34, common::Encode::HexDecode("7d9b42aaf72d0a2a42777ea49a999eeb22a33370")));
    root_account_with_pool_index_map_.insert(std::make_pair(35, common::Encode::HexDecode("809b76a62ea852598e8d8a163803818689bbaaf2")));
    root_account_with_pool_index_map_.insert(std::make_pair(36, common::Encode::HexDecode("42245623ffcb75221c7f43ed1c5d0f5630fb48cb")));
    root_account_with_pool_index_map_.insert(std::make_pair(37, common::Encode::HexDecode("01377ec6f4a8c51b3ec03fade42c139228bce58b")));
    root_account_with_pool_index_map_.insert(std::make_pair(38, common::Encode::HexDecode("abc08119ec9fd15e219c5ff9e077c3991daa736c")));
    root_account_with_pool_index_map_.insert(std::make_pair(39, common::Encode::HexDecode("184623b09a46771d2f22e69655387b180888f953")));
    root_account_with_pool_index_map_.insert(std::make_pair(40, common::Encode::HexDecode("212311d46bef067cef9a1d4de97876be943441ff")));
    root_account_with_pool_index_map_.insert(std::make_pair(41, common::Encode::HexDecode("0b9322107fc37cacc92e39a875fab441484aacdb")));
    root_account_with_pool_index_map_.insert(std::make_pair(42, common::Encode::HexDecode("9b3fc9315fdef2d8fc31ae1f65256c61f9339808")));
    root_account_with_pool_index_map_.insert(std::make_pair(43, common::Encode::HexDecode("453bf2676f6e91eb2f5a59d539b472d84beef8ea")));
    root_account_with_pool_index_map_.insert(std::make_pair(44, common::Encode::HexDecode("2ce9cd0573d4924ef91f9a1f7c949f008cc53313")));
    root_account_with_pool_index_map_.insert(std::make_pair(45, common::Encode::HexDecode("e4b91565c284940fd629bf8c18d97a260926bd3a")));
    root_account_with_pool_index_map_.insert(std::make_pair(46, common::Encode::HexDecode("7703cf9410aabd10f30d1a28bb1def2c868276c7")));
    root_account_with_pool_index_map_.insert(std::make_pair(47, common::Encode::HexDecode("3cfaa38e1c5288155d9de0205fd1382f16e906be")));
    root_account_with_pool_index_map_.insert(std::make_pair(48, common::Encode::HexDecode("0e227a3a0fe70ea7687e6ae8f2281cd8cc7cffaa")));
    root_account_with_pool_index_map_.insert(std::make_pair(49, common::Encode::HexDecode("17c9bbc95d7778fc14ba039c3b100919700fe9af")));
    root_account_with_pool_index_map_.insert(std::make_pair(50, common::Encode::HexDecode("b0aaa9b4852eb9ba47128f006a27465e84b7b76f")));
    root_account_with_pool_index_map_.insert(std::make_pair(51, common::Encode::HexDecode("fc6a1a8d2b2684b69575f41683d4d9b432bd1f4b")));
    root_account_with_pool_index_map_.insert(std::make_pair(52, common::Encode::HexDecode("d5fe156af3ce2647bf553005b6f3877bc158f077")));
    root_account_with_pool_index_map_.insert(std::make_pair(53, common::Encode::HexDecode("5b44e564a97ff9e4ca517114af439690bad453fc")));
    root_account_with_pool_index_map_.insert(std::make_pair(54, common::Encode::HexDecode("f9d96202d191e7f3c3fc8637b8adf27aeaeefb14")));
    root_account_with_pool_index_map_.insert(std::make_pair(55, common::Encode::HexDecode("6cabae615c85553029ad393e6625e48da27898c6")));
    root_account_with_pool_index_map_.insert(std::make_pair(56, common::Encode::HexDecode("b60b0c2a1e447dd9ba26a8d3395aae5c429ea115")));
    root_account_with_pool_index_map_.insert(std::make_pair(57, common::Encode::HexDecode("4173aac87b514a8c190e07e7d5d713cd4c1ba859")));
    root_account_with_pool_index_map_.insert(std::make_pair(58, common::Encode::HexDecode("b916bd18a6f79fc8bb0d62520c0bdb51c4c33700")));
    root_account_with_pool_index_map_.insert(std::make_pair(59, common::Encode::HexDecode("a937bf1a1483f7533553adb59736f5c50897baf1")));
    root_account_with_pool_index_map_.insert(std::make_pair(60, common::Encode::HexDecode("daa5e93404433f7786a9c580c13c7f82d9496586")));
    root_account_with_pool_index_map_.insert(std::make_pair(61, common::Encode::HexDecode("400ba2a2593c2bf240b728b2ed1762e904946292")));
    root_account_with_pool_index_map_.insert(std::make_pair(62, common::Encode::HexDecode("50e089416d4b17eaee200fba0e97c08b9d9b7e98")));
    root_account_with_pool_index_map_.insert(std::make_pair(63, common::Encode::HexDecode("e8ff10e446513efeb66f37822d16e88784d7b1a3")));
    root_account_with_pool_index_map_.insert(std::make_pair(64, common::Encode::HexDecode("32fa5cb052b38b27403ddfcb059c51df817d407a")));
    root_account_with_pool_index_map_.insert(std::make_pair(65, common::Encode::HexDecode("5602f7ccf83c49d6704f86f711b6bbcaa0287ba3")));
    root_account_with_pool_index_map_.insert(std::make_pair(66, common::Encode::HexDecode("c396d906ece2dcb18e8eca07f879e2e684c723d6")));
    root_account_with_pool_index_map_.insert(std::make_pair(67, common::Encode::HexDecode("38cbe2674a860beab41314b5cbab88722ef853ab")));
    root_account_with_pool_index_map_.insert(std::make_pair(68, common::Encode::HexDecode("43d6474e8dd5db09f304d5a9954e1f9941979d2f")));
    root_account_with_pool_index_map_.insert(std::make_pair(69, common::Encode::HexDecode("d756b3e646096e5a1973d3b9f0859ab3d6b509c0")));
    root_account_with_pool_index_map_.insert(std::make_pair(70, common::Encode::HexDecode("0aec97f5adc6983e9a2ca5c7c5cae4c70dbbba65")));
    root_account_with_pool_index_map_.insert(std::make_pair(71, common::Encode::HexDecode("dcf6d912f3b029bd13bc776c30758d9001ba9348")));
    root_account_with_pool_index_map_.insert(std::make_pair(72, common::Encode::HexDecode("57bac7fb5586fcc99e6386c235c4295fd6d78eeb")));
    root_account_with_pool_index_map_.insert(std::make_pair(73, common::Encode::HexDecode("815e46468c12fe92a3badf9ed99e24055c6e1e93")));
    root_account_with_pool_index_map_.insert(std::make_pair(74, common::Encode::HexDecode("7d9a9d5e7b37d8ad9a8588f9cbf464d4229902bf")));
    root_account_with_pool_index_map_.insert(std::make_pair(75, common::Encode::HexDecode("00412707b2f8b1873636fdeecd3599c836778bf7")));
    root_account_with_pool_index_map_.insert(std::make_pair(76, common::Encode::HexDecode("70680fe114e06de922e20356aae39db3c5a2c4e2")));
    root_account_with_pool_index_map_.insert(std::make_pair(77, common::Encode::HexDecode("8454668a2595223f3871455a113572f65285f779")));
    root_account_with_pool_index_map_.insert(std::make_pair(78, common::Encode::HexDecode("ef00d6e609cc863d2e23a3ad40a4f31255037297")));
    root_account_with_pool_index_map_.insert(std::make_pair(79, common::Encode::HexDecode("938d9794182a9b5b434e11e5836607550bbd4bbd")));
    root_account_with_pool_index_map_.insert(std::make_pair(80, common::Encode::HexDecode("73dca13bef5d853fc80a3c1ebe3e4a96b4857494")));
    root_account_with_pool_index_map_.insert(std::make_pair(81, common::Encode::HexDecode("3aa457b7be0f8261c2f41e81341e8ca929e58628")));
    root_account_with_pool_index_map_.insert(std::make_pair(82, common::Encode::HexDecode("27d253b9bfb5fe2f7864135f2f19a027d2710247")));
    root_account_with_pool_index_map_.insert(std::make_pair(83, common::Encode::HexDecode("14429a464ec0c65138378792f4bc3cb3e6e72ed0")));
    root_account_with_pool_index_map_.insert(std::make_pair(84, common::Encode::HexDecode("2e1eaf693982a5d0e9ac2fe1ebba9727612e0e41")));
    root_account_with_pool_index_map_.insert(std::make_pair(85, common::Encode::HexDecode("9c01cbbc759c5910b25cdce2ca33581dc7b54e06")));
    root_account_with_pool_index_map_.insert(std::make_pair(86, common::Encode::HexDecode("9e325e7367d8f7408d84c6e9ec124e1c80cf54ac")));
    root_account_with_pool_index_map_.insert(std::make_pair(87, common::Encode::HexDecode("9679fc026d09e59bd2e600d32a698a901a8e1d5a")));
    root_account_with_pool_index_map_.insert(std::make_pair(88, common::Encode::HexDecode("b96b380ff60f3f0b186bc655f3c85eceac279351")));
    root_account_with_pool_index_map_.insert(std::make_pair(89, common::Encode::HexDecode("bb530333d7853da6d66f389b9b35acf6816116fe")));
    root_account_with_pool_index_map_.insert(std::make_pair(90, common::Encode::HexDecode("a73cc56dc18cb8b8ceb14286fe816d737fc077f5")));
    root_account_with_pool_index_map_.insert(std::make_pair(91, common::Encode::HexDecode("1b112df074889e50920384510f393ab1a64a83be")));
    root_account_with_pool_index_map_.insert(std::make_pair(92, common::Encode::HexDecode("f89e3d5ccf10813053a4b6dbcce4c828ed01e156")));
    root_account_with_pool_index_map_.insert(std::make_pair(93, common::Encode::HexDecode("9ea5590bc3b2803dfe117d941063299878c32819")));
    root_account_with_pool_index_map_.insert(std::make_pair(94, common::Encode::HexDecode("dc7ad2c6b212fcf2af141411945f130f9f2b4189")));
    root_account_with_pool_index_map_.insert(std::make_pair(95, common::Encode::HexDecode("a8e0d0adf56bb63b51dac64996b468e39e699de3")));
    root_account_with_pool_index_map_.insert(std::make_pair(96, common::Encode::HexDecode("b2afb3768c2f0a0a68f0a7ca267762cc9a6e092f")));
    root_account_with_pool_index_map_.insert(std::make_pair(97, common::Encode::HexDecode("61b1879c30ead3bddbeb428716f881e9230d58ee")));
    root_account_with_pool_index_map_.insert(std::make_pair(98, common::Encode::HexDecode("bf0e02cdd688755d73fae4456c76da2070bd5894")));
    root_account_with_pool_index_map_.insert(std::make_pair(99, common::Encode::HexDecode("6444912d7de9f9cdc2c703ef1151086fd83fc8bb")));
    root_account_with_pool_index_map_.insert(std::make_pair(100, common::Encode::HexDecode("785c08a2aa30eca9a7cdc6bf847de83ba42d7b88")));
    root_account_with_pool_index_map_.insert(std::make_pair(101, common::Encode::HexDecode("16b36da63a172dda761bd57c887ab86004716444")));
    root_account_with_pool_index_map_.insert(std::make_pair(102, common::Encode::HexDecode("85b9635756470d0d7e7543e933787f6913310cfe")));
    root_account_with_pool_index_map_.insert(std::make_pair(103, common::Encode::HexDecode("9b1b44474c5c5b4151d9fc587fa51b7ad20f29e9")));
    root_account_with_pool_index_map_.insert(std::make_pair(104, common::Encode::HexDecode("395927f7540d200847401080664730d7adb20b2c")));
    root_account_with_pool_index_map_.insert(std::make_pair(105, common::Encode::HexDecode("4a7435d9395000bf251c738495c60d4cbf79a791")));
    root_account_with_pool_index_map_.insert(std::make_pair(106, common::Encode::HexDecode("ccbc9318e16b376137b5ab6abfadba47f5de1369")));
    root_account_with_pool_index_map_.insert(std::make_pair(107, common::Encode::HexDecode("e843d947597abc773b01121e33039d891bb91a8d")));
    root_account_with_pool_index_map_.insert(std::make_pair(108, common::Encode::HexDecode("7cad7c8d40ec0894f8d694ea8e9d6748085142a9")));
    root_account_with_pool_index_map_.insert(std::make_pair(109, common::Encode::HexDecode("1cc853cde06704fbc08590dc0571825a12d14b45")));
    root_account_with_pool_index_map_.insert(std::make_pair(110, common::Encode::HexDecode("fb826b6398df2c3b9a03a5f9b6670936ae1f5aa0")));
    root_account_with_pool_index_map_.insert(std::make_pair(111, common::Encode::HexDecode("e79e9d3ce9d7e0c51198f677e1e49a7f638e9fb1")));
    root_account_with_pool_index_map_.insert(std::make_pair(112, common::Encode::HexDecode("b9c4e98e9edfbdab1f0d74d82f3871c49b458c4c")));
    root_account_with_pool_index_map_.insert(std::make_pair(113, common::Encode::HexDecode("c75855d0fb85a2488e2aa0e74df9cf69234f6dc0")));
    root_account_with_pool_index_map_.insert(std::make_pair(114, common::Encode::HexDecode("7bf55a900d7cd0c32e2286f1e3a9eaac1ec3e745")));
    root_account_with_pool_index_map_.insert(std::make_pair(115, common::Encode::HexDecode("6397cefbbb4e5a6e7007732b498fc65a6b0652f3")));
    root_account_with_pool_index_map_.insert(std::make_pair(116, common::Encode::HexDecode("547f8f444b4aa898e5be92fc01f3524bf0f2c7bf")));
    root_account_with_pool_index_map_.insert(std::make_pair(117, common::Encode::HexDecode("3f01b0e5fdcf0684ee9bfc8a726c4445b69810b6")));
    root_account_with_pool_index_map_.insert(std::make_pair(118, common::Encode::HexDecode("64892d8fbc6777e3af71b7712f2c981e561fead9")));
    root_account_with_pool_index_map_.insert(std::make_pair(119, common::Encode::HexDecode("13a9f9344ec232f58b940a662b51c83f1d1417fa")));
    root_account_with_pool_index_map_.insert(std::make_pair(120, common::Encode::HexDecode("451b2f63beca7f2b142abf01226e78ede0e53e1e")));
    root_account_with_pool_index_map_.insert(std::make_pair(121, common::Encode::HexDecode("66a3a24eb45193ddcb00c6aa3ab7c7695d51a93a")));
    root_account_with_pool_index_map_.insert(std::make_pair(122, common::Encode::HexDecode("648d4d7bf50c2669eb279c4f108353bca2ce5b79")));
    root_account_with_pool_index_map_.insert(std::make_pair(123, common::Encode::HexDecode("18f2db129f61285d8b40caa1d18f90f31e91df48")));
    root_account_with_pool_index_map_.insert(std::make_pair(124, common::Encode::HexDecode("9073f1adef039c4d9e1c5d7d63e8a516d52e435e")));
    root_account_with_pool_index_map_.insert(std::make_pair(125, common::Encode::HexDecode("060f7e230fbb50af831c2d8b8c032e862af61445")));
    root_account_with_pool_index_map_.insert(std::make_pair(126, common::Encode::HexDecode("b3a00c52c68ee08464ab7d52c134f3240308a68e")));
    root_account_with_pool_index_map_.insert(std::make_pair(127, common::Encode::HexDecode("f7aafcc8a0f10d52d21c44b95aad8ac3c6310080")));
    root_account_with_pool_index_map_.insert(std::make_pair(128, common::Encode::HexDecode("9ba16ab8711667ac9b36fcd3b3654f5aec54e537")));
    root_account_with_pool_index_map_.insert(std::make_pair(129, common::Encode::HexDecode("88eff7d4e95a3ced4efb365abc386db9548b3e66")));
    root_account_with_pool_index_map_.insert(std::make_pair(130, common::Encode::HexDecode("5aca3c04996fa853d585b8cb7f02d273d5345ad2")));
    root_account_with_pool_index_map_.insert(std::make_pair(131, common::Encode::HexDecode("35bbf8a659210d5777fd73cc878279caa7edc49c")));
    root_account_with_pool_index_map_.insert(std::make_pair(132, common::Encode::HexDecode("c5a42fe58ca451eb3dcd5678af7eff546e4413ea")));
    root_account_with_pool_index_map_.insert(std::make_pair(133, common::Encode::HexDecode("013f64a862a40839cb1b5b52fee8fe3b659b7726")));
    root_account_with_pool_index_map_.insert(std::make_pair(134, common::Encode::HexDecode("35b7306b6f3d9f2d707656cde3aadc054ad640ce")));
    root_account_with_pool_index_map_.insert(std::make_pair(135, common::Encode::HexDecode("27f2e58f47194a6cca9323641ae1322935d6c613")));
    root_account_with_pool_index_map_.insert(std::make_pair(136, common::Encode::HexDecode("26e978c1365ca817385fb1773b2a30dfe770d1d1")));
    root_account_with_pool_index_map_.insert(std::make_pair(137, common::Encode::HexDecode("809832ded2d0ab6fb292ff70545a01c4f73a85a3")));
    root_account_with_pool_index_map_.insert(std::make_pair(138, common::Encode::HexDecode("f4c50f58f26eaa6c7830d0c0e05678966d3a1039")));
    root_account_with_pool_index_map_.insert(std::make_pair(139, common::Encode::HexDecode("a633f6ef52e8276def1d771107f2079708d4303b")));
    root_account_with_pool_index_map_.insert(std::make_pair(140, common::Encode::HexDecode("8e0632b475c77148f43bf28eeb8d0c89532059cb")));
    root_account_with_pool_index_map_.insert(std::make_pair(141, common::Encode::HexDecode("08ce96a0857d814543835093a6ebd2ed462c1aa2")));
    root_account_with_pool_index_map_.insert(std::make_pair(142, common::Encode::HexDecode("d21c7be44503d4c3279488de885ce8b0c3aadbc5")));
    root_account_with_pool_index_map_.insert(std::make_pair(143, common::Encode::HexDecode("2b4b478af79e6062888533203bcce721d4b52eb3")));
    root_account_with_pool_index_map_.insert(std::make_pair(144, common::Encode::HexDecode("457112066398da294d62dc2c361e3ef789794185")));
    root_account_with_pool_index_map_.insert(std::make_pair(145, common::Encode::HexDecode("ac714538e13369cf82401ea093b9cdf53e31a943")));
    root_account_with_pool_index_map_.insert(std::make_pair(146, common::Encode::HexDecode("82ea3f1d59953a893dff089a96edeebd02a3b738")));
    root_account_with_pool_index_map_.insert(std::make_pair(147, common::Encode::HexDecode("6b986b1469a8c2bbbffa0c91fc39ddf3bee2fcdc")));
    root_account_with_pool_index_map_.insert(std::make_pair(148, common::Encode::HexDecode("f6a3ca0dec87def3b787b837103d5ca1759ef63e")));
    root_account_with_pool_index_map_.insert(std::make_pair(149, common::Encode::HexDecode("3d006fc1cec240fc8c97fadb9d8350227e2b6345")));
    root_account_with_pool_index_map_.insert(std::make_pair(150, common::Encode::HexDecode("e7118777eafeb2a6e6ae8ab0377572e898bcb748")));
    root_account_with_pool_index_map_.insert(std::make_pair(151, common::Encode::HexDecode("ecbbde4ec49fa30ca3792cf10bcada7af42eb4a3")));
    root_account_with_pool_index_map_.insert(std::make_pair(152, common::Encode::HexDecode("ebda7e37214fb34cb373e06b1eddb81472940641")));
    root_account_with_pool_index_map_.insert(std::make_pair(153, common::Encode::HexDecode("8d50766747041ac13cc0bf3080d0dacf6ff2e276")));
    root_account_with_pool_index_map_.insert(std::make_pair(154, common::Encode::HexDecode("ea914625f7039bdcfae55ee3b33743935f96c900")));
    root_account_with_pool_index_map_.insert(std::make_pair(155, common::Encode::HexDecode("7f5efe777bcbe731f97c44e86523e2fb61508ee8")));
    root_account_with_pool_index_map_.insert(std::make_pair(156, common::Encode::HexDecode("9256d0ba708492820815f255a91a1c6354b6b33e")));
    root_account_with_pool_index_map_.insert(std::make_pair(157, common::Encode::HexDecode("94ac5bca8eb4f3e6af00c29e3dd91cad1b4a3609")));
    root_account_with_pool_index_map_.insert(std::make_pair(158, common::Encode::HexDecode("8910d08816bfa0dd1df545418e24fdf8abbe47ec")));
    root_account_with_pool_index_map_.insert(std::make_pair(159, common::Encode::HexDecode("836b562e96e790aac8a8d5b8426cb4de2ef394c0")));
    root_account_with_pool_index_map_.insert(std::make_pair(160, common::Encode::HexDecode("e31ae623619b90e3e200139f2f50b922362ea0d4")));
    root_account_with_pool_index_map_.insert(std::make_pair(161, common::Encode::HexDecode("ae180a957ca69706dee40579bec934b92445b548")));
    root_account_with_pool_index_map_.insert(std::make_pair(162, common::Encode::HexDecode("c331bca7cd713105173340977467da229846f806")));
    root_account_with_pool_index_map_.insert(std::make_pair(163, common::Encode::HexDecode("1cb1df6c6e38d19fb16f5cb6f5fb41795039b9be")));
    root_account_with_pool_index_map_.insert(std::make_pair(164, common::Encode::HexDecode("857babb59d0f82557863d61f131d716880836196")));
    root_account_with_pool_index_map_.insert(std::make_pair(165, common::Encode::HexDecode("81a716ee9a8769d8daaa1bdd15047b795c13bb6f")));
    root_account_with_pool_index_map_.insert(std::make_pair(166, common::Encode::HexDecode("5624a212b534c63ab0d77e776dd2cef48ef499cd")));
    root_account_with_pool_index_map_.insert(std::make_pair(167, common::Encode::HexDecode("600f863ae104b8be0b7e002cb0b555c2b308540b")));
    root_account_with_pool_index_map_.insert(std::make_pair(168, common::Encode::HexDecode("948d89ed8d0d0f68fa7e5ef95b3d400aca791a04")));
    root_account_with_pool_index_map_.insert(std::make_pair(169, common::Encode::HexDecode("3456cd79ad4c225322dd7bfd11ec4c1034bad837")));
    root_account_with_pool_index_map_.insert(std::make_pair(170, common::Encode::HexDecode("0ab4fcd3c8f9c76fe7657e230ed00fb3b9bbda36")));
    root_account_with_pool_index_map_.insert(std::make_pair(171, common::Encode::HexDecode("ace3667a193771453704ef4f86ba9d62b34b6f6f")));
    root_account_with_pool_index_map_.insert(std::make_pair(172, common::Encode::HexDecode("4d5f8b1732e3493b0a78bd29f73226e9f5e214cb")));
    root_account_with_pool_index_map_.insert(std::make_pair(173, common::Encode::HexDecode("799824a8c329dee796ee2885bbb6ae038c0e3f0d")));
    root_account_with_pool_index_map_.insert(std::make_pair(174, common::Encode::HexDecode("b748a48072cf4672da533e52e2bb085759bcb6d6")));
    root_account_with_pool_index_map_.insert(std::make_pair(175, common::Encode::HexDecode("51f69609686039dcea72306412ad9afe4eed9f08")));
    root_account_with_pool_index_map_.insert(std::make_pair(176, common::Encode::HexDecode("aa650cda5e00d0235f3a5c1f7ff4e0e5d2456538")));
    root_account_with_pool_index_map_.insert(std::make_pair(177, common::Encode::HexDecode("5e32527c98f6c531aa0042c1ee5f8949bb22d1dc")));
    root_account_with_pool_index_map_.insert(std::make_pair(178, common::Encode::HexDecode("da7aad9164d6e81f4da5db0afe736b6fcb9cde7d")));
    root_account_with_pool_index_map_.insert(std::make_pair(179, common::Encode::HexDecode("b5ddad0f3dead09d84be4ccd88097c4f6c6c4b8e")));
    root_account_with_pool_index_map_.insert(std::make_pair(180, common::Encode::HexDecode("7e7f0eaab1cf668bf00fe99ebe2de9ab20b3e319")));
    root_account_with_pool_index_map_.insert(std::make_pair(181, common::Encode::HexDecode("bfe1f3a817049b4956564686dde7ef383710cd76")));
    root_account_with_pool_index_map_.insert(std::make_pair(182, common::Encode::HexDecode("0c44c42ba49edcea89f88d1371d8a678954e0b0e")));
    root_account_with_pool_index_map_.insert(std::make_pair(183, common::Encode::HexDecode("17e5c77a81ba2e122763dcda9728173b45fcf14a")));
    root_account_with_pool_index_map_.insert(std::make_pair(184, common::Encode::HexDecode("5b7d41ab8bc14496ef15ec86354cc7f4c69bb4a8")));
    root_account_with_pool_index_map_.insert(std::make_pair(185, common::Encode::HexDecode("eee36c64039584e40f5b792bf1ea1458bb171aed")));
    root_account_with_pool_index_map_.insert(std::make_pair(186, common::Encode::HexDecode("81e36e444664fc84093ed832f96752f18d8d53ce")));
    root_account_with_pool_index_map_.insert(std::make_pair(187, common::Encode::HexDecode("be703e674f4f917fb6e6fbbfaf3ddf757d4c24a8")));
    root_account_with_pool_index_map_.insert(std::make_pair(188, common::Encode::HexDecode("aa6ed6274cc4ca6ecafb3ba10ea3b60344d9d656")));
    root_account_with_pool_index_map_.insert(std::make_pair(189, common::Encode::HexDecode("c59317896c068bf5dc51a13a38df58978f0723a0")));
    root_account_with_pool_index_map_.insert(std::make_pair(190, common::Encode::HexDecode("675a6c94425c19424024920a8971d1cda7ca2c05")));
    root_account_with_pool_index_map_.insert(std::make_pair(191, common::Encode::HexDecode("096a647fbc9717cff772865fc3c8df8dc8a9e53c")));
    root_account_with_pool_index_map_.insert(std::make_pair(192, common::Encode::HexDecode("0adb2f2c7da8368e691e84f79914dbd69474116b")));
    root_account_with_pool_index_map_.insert(std::make_pair(193, common::Encode::HexDecode("500630cb73a3cae940abf45c685f234d463f1409")));
    root_account_with_pool_index_map_.insert(std::make_pair(194, common::Encode::HexDecode("2b8fd60f9c4a2c11a6094da839ab82f51daaf67b")));
    root_account_with_pool_index_map_.insert(std::make_pair(195, common::Encode::HexDecode("5460483c986ce3e808ecd6b98ed217d4fd43ef07")));
    root_account_with_pool_index_map_.insert(std::make_pair(196, common::Encode::HexDecode("f89e5ab37328fe5095c8bfe3b15cd7b1f9d0bafe")));
    root_account_with_pool_index_map_.insert(std::make_pair(197, common::Encode::HexDecode("09c40ca282d01d0c7f292b379f3db1bb1b39bbb3")));
    root_account_with_pool_index_map_.insert(std::make_pair(198, common::Encode::HexDecode("f11b24dc86502a74adb62e5bb55d475f24bbb509")));
    root_account_with_pool_index_map_.insert(std::make_pair(199, common::Encode::HexDecode("fad8995c12056566c7aa12747bd03026ffaf57f7")));
    root_account_with_pool_index_map_.insert(std::make_pair(200, common::Encode::HexDecode("0d349b546a48e67bfb6cb1b7e99301453671a1aa")));
    root_account_with_pool_index_map_.insert(std::make_pair(201, common::Encode::HexDecode("e52bb4604912c5a189f57f1896cd09a3a0821c0e")));
    root_account_with_pool_index_map_.insert(std::make_pair(202, common::Encode::HexDecode("cf6c9eedbc17af516d08c77e77dcc0e3c8145b69")));
    root_account_with_pool_index_map_.insert(std::make_pair(203, common::Encode::HexDecode("0d7913dfa9bed304af19f9a5139bbac2565231bd")));
    root_account_with_pool_index_map_.insert(std::make_pair(204, common::Encode::HexDecode("f9c9ed68b162ee4a13beb7ff3e0003fbc87dac18")));
    root_account_with_pool_index_map_.insert(std::make_pair(205, common::Encode::HexDecode("cfa8ccccf15a4ca3d3781eccf7dd217644210277")));
    root_account_with_pool_index_map_.insert(std::make_pair(206, common::Encode::HexDecode("3f84c79b4a83ac731e2fc16c5a86f3c92d8027f6")));
    root_account_with_pool_index_map_.insert(std::make_pair(207, common::Encode::HexDecode("ba589599d7a7f2497ccc5b9cbf1b942096672fd5")));
    root_account_with_pool_index_map_.insert(std::make_pair(208, common::Encode::HexDecode("a9956e20597226847fd9b9398fb3fd1edbe956d6")));
    root_account_with_pool_index_map_.insert(std::make_pair(209, common::Encode::HexDecode("51b3db5ad51e6018ead1ff1163ac48d25de6c4be")));
    root_account_with_pool_index_map_.insert(std::make_pair(210, common::Encode::HexDecode("a0ec830657e3a8d10c3596ae7c39d43b59292026")));
    root_account_with_pool_index_map_.insert(std::make_pair(211, common::Encode::HexDecode("7c11e320b60eacecb71d9de1ea98b1082b21ad64")));
    root_account_with_pool_index_map_.insert(std::make_pair(212, common::Encode::HexDecode("ddf009850afdbf20e797b9a4d07eb1b6a27c2f41")));
    root_account_with_pool_index_map_.insert(std::make_pair(213, common::Encode::HexDecode("eb2b839029475e4c14b86caddc500789ec7cecf5")));
    root_account_with_pool_index_map_.insert(std::make_pair(214, common::Encode::HexDecode("1016b5eca00225f68d5bb876084eed8adcca29ef")));
    root_account_with_pool_index_map_.insert(std::make_pair(215, common::Encode::HexDecode("546317cb1005e6b8a47581f96658c30aa014cd4e")));
    root_account_with_pool_index_map_.insert(std::make_pair(216, common::Encode::HexDecode("e6c019f6499920e7c218adcb8eb21ed497f3c498")));
    root_account_with_pool_index_map_.insert(std::make_pair(217, common::Encode::HexDecode("d045b9ee164bdb5a2ab4810a81a2c4c3737d8223")));
    root_account_with_pool_index_map_.insert(std::make_pair(218, common::Encode::HexDecode("59e7bdee6379a1ee72651fb2a8c4c016cf5ab99d")));
    root_account_with_pool_index_map_.insert(std::make_pair(219, common::Encode::HexDecode("a4b36cc40c96d3458cc8c404f1be1be0eaaf2903")));
    root_account_with_pool_index_map_.insert(std::make_pair(220, common::Encode::HexDecode("ec5dcecded13fbb20c80b3172341a1e035c5e109")));
    root_account_with_pool_index_map_.insert(std::make_pair(221, common::Encode::HexDecode("ef0a18270f76960e309b650c51b57b020e067fcb")));
    root_account_with_pool_index_map_.insert(std::make_pair(222, common::Encode::HexDecode("0fbaabbdca134b6362c4405f958c03bdd152781d")));
    root_account_with_pool_index_map_.insert(std::make_pair(223, common::Encode::HexDecode("b26a0d965f87b1f6a4490bbb0cb560dac5a97da2")));
    root_account_with_pool_index_map_.insert(std::make_pair(224, common::Encode::HexDecode("eadc611084465a9788093e2801eaa81525373914")));
    root_account_with_pool_index_map_.insert(std::make_pair(225, common::Encode::HexDecode("293b28513bae55bf638d1e81c1d53421345299ac")));
    root_account_with_pool_index_map_.insert(std::make_pair(226, common::Encode::HexDecode("9463912657210a269f7d6dc137dce4ad7702fbd7")));
    root_account_with_pool_index_map_.insert(std::make_pair(227, common::Encode::HexDecode("074d9aa20d8e5fd71a598152a29ff03724449792")));
    root_account_with_pool_index_map_.insert(std::make_pair(228, common::Encode::HexDecode("1678b0f0cf566a9a2c6ca981ef5e73897abb480a")));
    root_account_with_pool_index_map_.insert(std::make_pair(229, common::Encode::HexDecode("344baa8b88bc7f555530fc03758dd814d3ed5077")));
    root_account_with_pool_index_map_.insert(std::make_pair(230, common::Encode::HexDecode("34055a9f886fe00400991d8e3a61c9f97c31ff53")));
    root_account_with_pool_index_map_.insert(std::make_pair(231, common::Encode::HexDecode("59f8c7e6891ba378b582f1a7180d84ba6ccb0c2a")));
    root_account_with_pool_index_map_.insert(std::make_pair(232, common::Encode::HexDecode("0368831f15969b40d39855bdd8cc8bdb39291bd3")));
    root_account_with_pool_index_map_.insert(std::make_pair(233, common::Encode::HexDecode("63b00807940f89a93fed714f43a17dbe1d2aab63")));
    root_account_with_pool_index_map_.insert(std::make_pair(234, common::Encode::HexDecode("1541e5ce49efa3dfdbe0836e69bd4a6ea0103a0c")));
    root_account_with_pool_index_map_.insert(std::make_pair(235, common::Encode::HexDecode("afddddeff06cc1d7888b4727d0fa51b5f6d380d7")));
    root_account_with_pool_index_map_.insert(std::make_pair(236, common::Encode::HexDecode("d9fedb03a78368f01f7cbfb2545ced4d8fe167ec")));
    root_account_with_pool_index_map_.insert(std::make_pair(237, common::Encode::HexDecode("ebd04facc434fc645033e2d3aa56f47c367ac439")));
    root_account_with_pool_index_map_.insert(std::make_pair(238, common::Encode::HexDecode("7e1020e71ddb29b72b3dbaa18aad3b8363311199")));
    root_account_with_pool_index_map_.insert(std::make_pair(239, common::Encode::HexDecode("aaade18d11ef5b5195437678889ef9d409cbca40")));
    root_account_with_pool_index_map_.insert(std::make_pair(240, common::Encode::HexDecode("1ec39d1d17ba57b9df68ce478e9acc1b8cf310d6")));
    root_account_with_pool_index_map_.insert(std::make_pair(241, common::Encode::HexDecode("1c15a7e7b324a33dbbad21f10487d5d0b17374cd")));
    root_account_with_pool_index_map_.insert(std::make_pair(242, common::Encode::HexDecode("6001c97eb4c7577c146970da4bed59b90a890c5b")));
    root_account_with_pool_index_map_.insert(std::make_pair(243, common::Encode::HexDecode("5baa15354e4f41749c8910ca1b378c4fc700e719")));
    root_account_with_pool_index_map_.insert(std::make_pair(244, common::Encode::HexDecode("fdede1158999a3b11cbedcd8d250a0bc9a81dae3")));
    root_account_with_pool_index_map_.insert(std::make_pair(245, common::Encode::HexDecode("c7d0e4123d92a6c8983e2da9b014a75fae041e91")));
    root_account_with_pool_index_map_.insert(std::make_pair(246, common::Encode::HexDecode("23751e9b2f980529c9b9ca327da336d2c5a72e3d")));
    root_account_with_pool_index_map_.insert(std::make_pair(247, common::Encode::HexDecode("8bfe5d658bdd27a08b1ef467e98e9d657e9aa069")));
    root_account_with_pool_index_map_.insert(std::make_pair(248, common::Encode::HexDecode("dcb9a1ac4eb24a6a67a4c82ab21933a255cba1b5")));
    root_account_with_pool_index_map_.insert(std::make_pair(249, common::Encode::HexDecode("f7f4e73d366a885c1d06cd35d8beb25639de68e5")));
    root_account_with_pool_index_map_.insert(std::make_pair(250, common::Encode::HexDecode("9b10901c50fde46131c1e560cd1e6085931cabf1")));
    root_account_with_pool_index_map_.insert(std::make_pair(251, common::Encode::HexDecode("8f1762478a3fad0d6ccd6e1b9eb2868d72a77a3a")));
    root_account_with_pool_index_map_.insert(std::make_pair(252, common::Encode::HexDecode("873dc3323ed17586e11f6db1bad2cb5e1ca67048")));
    root_account_with_pool_index_map_.insert(std::make_pair(253, common::Encode::HexDecode("dcdaf3136202aaa45fa73a5638dea19e45a78575")));
    root_account_with_pool_index_map_.insert(std::make_pair(254, common::Encode::HexDecode("ea972179b7f0eaa6ab04a5a70076119c1340b18a")));
    root_account_with_pool_index_map_.insert(std::make_pair(255, common::Encode::HexDecode("553dcb2dd29f1da51aa6b6b182bfba7b6e9af6df")));

    //     while (root_account_with_pool_index_map_.size() < common::kImmutablePoolSize) {
    //         security::PrivateKey prikey;
    //         security::PublicKey pubkey(prikey);
    //         std::string pubkey_str;
    //         pubkey.Serialize(pubkey_str, false);
    //         std::string prikey_str;
    //         prikey.Serialize(prikey_str);
    // 
    //         std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
    //         std::string address1 = security::Secp256k1::Instance()->ToAddressWithPrivateKey(prikey_str);
    //         assert(address == address1);
    //         auto pool_index = common::GetPoolIndex(address);
    //         auto iter = root_account_with_pool_index_map_.find(pool_index);
    //         if (iter != root_account_with_pool_index_map_.end()) {
    //             continue;
    //         }
    // 
    //         root_account_with_pool_index_map_.insert(std::make_pair(pool_index, prikey_str));
    //     }
    // 
    //     for (auto iter = root_account_with_pool_index_map_.begin(); iter != root_account_with_pool_index_map_.end(); ++iter) {
    //         std::cout << "root_account_with_pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(iter->second) << "\")));" << std::endl;
    //     }

    //     for (auto iter = root_account_with_pool_index_map_.begin(); iter != root_account_with_pool_index_map_.end(); ++iter) {
    //         std::cout << "root_account_with_pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(security::Secp256k1::Instance()->ToAddressWithPrivateKey(iter->second)) << "\")));" << std::endl;
    //    }
}

};  // namespace init

};  // namespace tenon
