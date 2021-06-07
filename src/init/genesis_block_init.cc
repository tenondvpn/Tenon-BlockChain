#include "init/genesis_block_init.h"

#include "common/encode.h"
#include "block/account_manager.h"
#include "init/init_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "bft/bft_manager.h"
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

int GenesisBlockInit::CreateGenesisBlocks(uint32_t net_id) {
    if (net_id == network::kRootCongressNetworkId) {
        common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
        return CreateRootGenesisBlocks();
    }

    common::GlobalInfo::Instance()->set_network_id(net_id);
    return CreateShardGenesisBlocks(net_id);
}

int GenesisBlockInit::GenerateRootSingleBlock() {
    GenerateRootAccounts();
    // for root single block chain
    std::string root_pre_hash;
    {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
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
        tenon_block.set_prehash("");
        tenon_block.set_version(common::kTransactionVersion);
        tenon_block.set_elect_ver(0);
        tenon_block.set_agg_pubkey("");
        tenon_block.set_agg_sign_challenge("");
        tenon_block.set_agg_sign_response("");
        tenon_block.set_pool_index(common::kRootChainPoolIndex);
        tenon_block.set_height(0);
        tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        std::cout << "root height 0: " << common::Encode::HexEncode(tenon_block.SerializeAsString()) << std::endl;
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("AddGenisisBlock error.");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("GetBlockInfo error.");
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address failed! [%s]", common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance), block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        if (balance != 0) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        root_pre_hash = bft::GetBlockHash(tenon_block);
    }

    {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
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
        auto now_tm = common::TimeUtils::TimestampSeconds() - tmblock::kTimeBlockCreatePeriodSeconds;
        all_exits_attr->set_value(std::to_string(now_tm));
        tenon_block.set_prehash(root_pre_hash);
        tenon_block.set_version(common::kTransactionVersion);
        tenon_block.set_elect_ver(0);
        tenon_block.set_agg_pubkey("");
        tenon_block.set_agg_sign_challenge("");
        tenon_block.set_agg_sign_response("");
        tenon_block.set_pool_index(common::kRootChainPoolIndex);
        tenon_block.set_height(1);
        tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        std::cout << "root height 1: " << common::Encode::HexEncode(tenon_block.SerializeAsString()) << std::endl;
        tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(1, now_tm);
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("AddGenisisBlock error");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("GetBlockInfo error");
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }

        if (balance != 0) {
            INIT_ERROR("get address balance failed! [%s]", common::Encode::HexEncode(root::kRootChainSingleBlockTxAddress).c_str());
            return kInitError;
        }
    }
}

int GenesisBlockInit::CreateRootGenesisBlocks() {
    GenerateRootAccounts();
    uint64_t genesis_account_balance = 0llu;
    uint64_t all_balance = 0llu;
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        auto iter = root_account_with_pool_index_map_.find(i);
        std::string address = iter->second;
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
        tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        tenon_block.set_prehash("");
        tenon_block.set_version(common::kTransactionVersion);
        tenon_block.set_elect_ver(0);
        tenon_block.set_agg_pubkey("");
        tenon_block.set_agg_sign_challenge("");
        tenon_block.set_agg_sign_response("");
        tenon_block.set_pool_index(iter->first);
        tenon_block.set_height(0);
        tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("add genesis block failed!");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            iter->first,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("get pool block info failed! [%u]", iter->first);
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            INIT_ERROR("get address info failed! [%s]", common::Encode::HexEncode(address).c_str());
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

    if (all_balance != 0) {
        INIT_ERROR("balance all error[%llu][%llu]", all_balance, common::kGenesisFoundationMaxTenon);
        return kInitError;
    }

    return GenerateRootSingleBlock();
}

int GenesisBlockInit::CreateShardGenesisBlocks(uint32_t net_id) {
    InitGenesisAccount();
    uint64_t genesis_account_balance = common::kGenesisFoundationMaxTenon / pool_index_map_.size();
    uint64_t all_balance = 0llu;
    for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        std::string address = iter->second;
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
        tenon_block.set_prehash("");
        tenon_block.set_version(common::kTransactionVersion);
        tenon_block.set_elect_ver(0);
        tenon_block.set_agg_pubkey("");
        tenon_block.set_agg_sign_challenge("");
        tenon_block.set_agg_sign_response("");
        tenon_block.set_pool_index(iter->first);
        tenon_block.set_height(0);
        tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            INIT_ERROR("AddGenisisBlock error.");
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            iter->first,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            INIT_ERROR("GetBlockInfo error.");
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

    return GenerateRootSingleBlock();
}

void GenesisBlockInit::InitGenesisAccount() {
    pool_index_map_.insert(std::make_pair(0, common::Encode::HexDecode("b5de4a5c8efe2ba7fd443f3faa70b8c133a6ebba")));
    pool_index_map_.insert(std::make_pair(1, common::Encode::HexDecode("0e7ec48d4de59141a491acfaed6c23912508c5df")));
    pool_index_map_.insert(std::make_pair(2, common::Encode::HexDecode("72049efff9eab2f61de68d58ae9b188d164d4f9e")));
    pool_index_map_.insert(std::make_pair(3, common::Encode::HexDecode("25f31acff6fff5c315cbd2f6bb8c32d7b51b14bd")));
    pool_index_map_.insert(std::make_pair(4, common::Encode::HexDecode("d729fb8eab4c40a925dbebefe35d2d326698fbd4")));
    pool_index_map_.insert(std::make_pair(5, common::Encode::HexDecode("97c5040324b1057c112f0a5bfb6081eefd2dc9e4")));
    pool_index_map_.insert(std::make_pair(6, common::Encode::HexDecode("20c7a235433b4baf979178a6c58c5048a6f13f9b")));
    pool_index_map_.insert(std::make_pair(7, common::Encode::HexDecode("5e3eeea9ebb14319b600318e6b3e7e49baabb407")));
    pool_index_map_.insert(std::make_pair(8, common::Encode::HexDecode("6ffe2bb598663760e3becb6a25dbfa38a545b5dd")));
    pool_index_map_.insert(std::make_pair(9, common::Encode::HexDecode("00b7500ee49e60050b2db95507db26bf2ddca570")));
    pool_index_map_.insert(std::make_pair(10, common::Encode::HexDecode("b3fbf1eb08794b0d74fa4cf9a06557ab13c4daf8")));
    pool_index_map_.insert(std::make_pair(11, common::Encode::HexDecode("c73e30716f0abb43d914d1eb8a452a5c5ad07beb")));
    pool_index_map_.insert(std::make_pair(12, common::Encode::HexDecode("1ca01f17f0b23d29ce5304bd16139e86cfb7133b")));
    pool_index_map_.insert(std::make_pair(13, common::Encode::HexDecode("28c028767fc287dc59b01868e2169acabe4da827")));
    pool_index_map_.insert(std::make_pair(14, common::Encode::HexDecode("52ccd8b83b1c7253764eb41d73e44cd1fbefc864")));
    pool_index_map_.insert(std::make_pair(15, common::Encode::HexDecode("2273f20ff3778a067b584d35fda8bfaf89aaa6ad")));
    pool_index_map_.insert(std::make_pair(16, common::Encode::HexDecode("bf081af158be4d600dcc0d9782b8a360c5178a66")));
    pool_index_map_.insert(std::make_pair(17, common::Encode::HexDecode("a98f74517b192dc2f057c4e8632e7348c9b83d7a")));
    pool_index_map_.insert(std::make_pair(18, common::Encode::HexDecode("a0a651bdf3136b4101bfd1f64d0011c1095d5a19")));
    pool_index_map_.insert(std::make_pair(19, common::Encode::HexDecode("3876b4c9b3d6a2de3cb32d35524a50f29a361843")));
    pool_index_map_.insert(std::make_pair(20, common::Encode::HexDecode("9b4eab0bad3634a3c5b3ae6f9ae39fc7a54a0432")));
    pool_index_map_.insert(std::make_pair(21, common::Encode::HexDecode("9a4de39962487f6799c2a923361691178037e1d0")));
    pool_index_map_.insert(std::make_pair(22, common::Encode::HexDecode("f8b62a3ab75374210ea0256bc923fe7e1b5814d8")));
    pool_index_map_.insert(std::make_pair(23, common::Encode::HexDecode("c98790a3e45fe24d4dbaefd340c03207de7df03e")));
    pool_index_map_.insert(std::make_pair(24, common::Encode::HexDecode("687c1b9ead7e28bb060a926e0c5254b1744e497b")));
    pool_index_map_.insert(std::make_pair(25, common::Encode::HexDecode("0d7f35760ec54ea5815552d8324b0ecd01f700b6")));
    pool_index_map_.insert(std::make_pair(26, common::Encode::HexDecode("43a37388d49cf15b291747a1a05b2033b67c00bd")));
    pool_index_map_.insert(std::make_pair(27, common::Encode::HexDecode("b31d361fcfed425a0983d8703a50f465b100c1aa")));
    pool_index_map_.insert(std::make_pair(28, common::Encode::HexDecode("e755a3568b62f445be813a63da24891e7ef9358c")));
    pool_index_map_.insert(std::make_pair(29, common::Encode::HexDecode("c89f4fd4bb4797e49bf31437387bba99f3f1cbf2")));
    pool_index_map_.insert(std::make_pair(30, common::Encode::HexDecode("50b684982a69769a97913233515096e0ecba8b6d")));
    pool_index_map_.insert(std::make_pair(31, common::Encode::HexDecode("8125ad51f8c17600da3348667bc57450c9de6292")));
    pool_index_map_.insert(std::make_pair(32, common::Encode::HexDecode("6a150ee81f937c5d76a3f184dddfb96b554e000d")));
    pool_index_map_.insert(std::make_pair(33, common::Encode::HexDecode("03808184a8d82d53a6ec8ef61cfb8235effbd0b0")));
    pool_index_map_.insert(std::make_pair(34, common::Encode::HexDecode("b6eb5d738032f135a84a487687d34abd8e17b755")));
    pool_index_map_.insert(std::make_pair(35, common::Encode::HexDecode("05c3750a9ad93293df67b98fe6497c755cb00ecb")));
    pool_index_map_.insert(std::make_pair(36, common::Encode::HexDecode("2c1eaa3db5e9553c5fbcd97ad4011e1362da4679")));
    pool_index_map_.insert(std::make_pair(37, common::Encode::HexDecode("7254e1ddc0e2f966b58eb05a7755f9cca90b243d")));
    pool_index_map_.insert(std::make_pair(38, common::Encode::HexDecode("d982f20075be5b3ebcabea63bde64845c28f9ce2")));
    pool_index_map_.insert(std::make_pair(39, common::Encode::HexDecode("0b5dfe11cc3f82342d0d3e4f02e33301fa01b4ec")));
    pool_index_map_.insert(std::make_pair(40, common::Encode::HexDecode("1d0709908a1695137a7253a2e18bcecd39a18dbf")));
    pool_index_map_.insert(std::make_pair(41, common::Encode::HexDecode("c29329dcc70ecfaf1d2df379edb8a056c8a3f47a")));
    pool_index_map_.insert(std::make_pair(42, common::Encode::HexDecode("c59f987f1d3fd98190d2bf5c31c899c1a8034dcd")));
    pool_index_map_.insert(std::make_pair(43, common::Encode::HexDecode("bf6db75b130e615f0af2a5c5c68d5b654b40a26a")));
    pool_index_map_.insert(std::make_pair(44, common::Encode::HexDecode("427c93c386c396e8bebfa4f8e7ca82a8727228ba")));
    pool_index_map_.insert(std::make_pair(45, common::Encode::HexDecode("75d99a0220b0fd687aabeb152de2a5447d04e58f")));
    pool_index_map_.insert(std::make_pair(46, common::Encode::HexDecode("8bfa4bdf70d88d54e1f6531be019b7ab7a8280e9")));
    pool_index_map_.insert(std::make_pair(47, common::Encode::HexDecode("aa971601cb8f8525931f0556f63ee851d21dc94a")));
    pool_index_map_.insert(std::make_pair(48, common::Encode::HexDecode("8ec02d62e219809fec67ff4279a670e258123000")));
    pool_index_map_.insert(std::make_pair(49, common::Encode::HexDecode("58cb9b9fe98be96578abebc6789669720bc1d6e0")));
    pool_index_map_.insert(std::make_pair(50, common::Encode::HexDecode("f5a2aa496cb315b18b9bdb34d00919b3b959ac51")));
    pool_index_map_.insert(std::make_pair(51, common::Encode::HexDecode("ec46a0ca2b76217b7edc6d066b697a78887a2a2f")));
    pool_index_map_.insert(std::make_pair(52, common::Encode::HexDecode("aad0ded2b412a8cdba88f91ea88a92b37d04ecc5")));
    pool_index_map_.insert(std::make_pair(53, common::Encode::HexDecode("ffd02d83a13aaad5e93d71020225b7704c0dd88a")));
    pool_index_map_.insert(std::make_pair(54, common::Encode::HexDecode("8e64e645d8de0d42eea55ce1cf0988c095bc9f8e")));
    pool_index_map_.insert(std::make_pair(55, common::Encode::HexDecode("7f1051e4e93675bffa8886f874f9021492d388b1")));
    pool_index_map_.insert(std::make_pair(56, common::Encode::HexDecode("bc92f1e29c06bc01d2caee38061e3d2e3bd13955")));
    pool_index_map_.insert(std::make_pair(57, common::Encode::HexDecode("70cee41471e931c5fbae123b60333c1f70e94161")));
    pool_index_map_.insert(std::make_pair(58, common::Encode::HexDecode("b230aac010ba3b2129e81f693ad88ce8fc40bb09")));
    pool_index_map_.insert(std::make_pair(59, common::Encode::HexDecode("347fb2cebb8dbfda4601d21f72e242efce32a05d")));
    pool_index_map_.insert(std::make_pair(60, common::Encode::HexDecode("9103e50d5ecd4a727e6c15f34505790cee309f41")));
    pool_index_map_.insert(std::make_pair(61, common::Encode::HexDecode("3084ef997bea7dba961474503752c5b461eb00cc")));
    pool_index_map_.insert(std::make_pair(62, common::Encode::HexDecode("d9b0e361c9bbb65f23d964da204cc9acb38de8b1")));
    pool_index_map_.insert(std::make_pair(63, common::Encode::HexDecode("0803a24fd76dc41c7df4344184a50fae1da4b2a6")));
    pool_index_map_.insert(std::make_pair(64, common::Encode::HexDecode("2b92984930731155b9cc1d2ec7299b12d4228577")));
    pool_index_map_.insert(std::make_pair(65, common::Encode::HexDecode("696e6d31cc63810adafa49c94fd98e64e8ba5f7a")));
    pool_index_map_.insert(std::make_pair(66, common::Encode::HexDecode("5dc9e0a83913d48a0d3ef3fea0ce7221ab470b1e")));
    pool_index_map_.insert(std::make_pair(67, common::Encode::HexDecode("f059d1a839675f2fe7bcad3b59da48fc83be2903")));
    pool_index_map_.insert(std::make_pair(68, common::Encode::HexDecode("5445ef0f79f89188619e2ec2a278b313d77f9342")));
    pool_index_map_.insert(std::make_pair(69, common::Encode::HexDecode("5fc9017209067666b074444a137dcdb644e9db94")));
    pool_index_map_.insert(std::make_pair(70, common::Encode::HexDecode("f60bd83e44fbeb615714a1f361048dd779fee3c9")));
    pool_index_map_.insert(std::make_pair(71, common::Encode::HexDecode("a2240dc0c2595b04b98baa68a05e1bfb45aee040")));
    pool_index_map_.insert(std::make_pair(72, common::Encode::HexDecode("40310e381d38b55545bf0b7be1de4da53a0ae9ab")));
    pool_index_map_.insert(std::make_pair(73, common::Encode::HexDecode("61273cded2a843e077f002f33772aca0b84b39bc")));
    pool_index_map_.insert(std::make_pair(74, common::Encode::HexDecode("da00f87bd27f3f241cec38900496234fe8aef244")));
    pool_index_map_.insert(std::make_pair(75, common::Encode::HexDecode("b4e7784c0b64d1860809f62aff725237cb8a7824")));
    pool_index_map_.insert(std::make_pair(76, common::Encode::HexDecode("8b4f59a2ab3285801a6fd1f882b0bc733d0f2c2e")));
    pool_index_map_.insert(std::make_pair(77, common::Encode::HexDecode("5636395eed229963b1747a3e7d92f681e5ec24a5")));
    pool_index_map_.insert(std::make_pair(78, common::Encode::HexDecode("2f290dae63419537bc4be257acbda012c5bbb4c8")));
    pool_index_map_.insert(std::make_pair(79, common::Encode::HexDecode("d3c16780e104b7752bb6596ad6884d1cfab8becc")));
    pool_index_map_.insert(std::make_pair(80, common::Encode::HexDecode("847a457330a8c9dcd18f93f5924c9581d98eb0fc")));
    pool_index_map_.insert(std::make_pair(81, common::Encode::HexDecode("8238e73191edb2aebca76e81c0cffcf2e8f42a07")));
    pool_index_map_.insert(std::make_pair(82, common::Encode::HexDecode("3578838426ca5cdf5f6b9453e943b6820b18fcd4")));
    pool_index_map_.insert(std::make_pair(83, common::Encode::HexDecode("b0865a7732afabe8e999954401c59e22e1c09018")));
    pool_index_map_.insert(std::make_pair(84, common::Encode::HexDecode("dca5ecf650cfa69bca75cc8d521f9d0f18e71afc")));
    pool_index_map_.insert(std::make_pair(85, common::Encode::HexDecode("8af379dff9f9c606bb2081c819bc37c99697eb73")));
    pool_index_map_.insert(std::make_pair(86, common::Encode::HexDecode("42c9cc9877cc81a75addcd894a2cebb50a44ab3a")));
    pool_index_map_.insert(std::make_pair(87, common::Encode::HexDecode("4b778cf8fa01fb0c0892935630390bb44af7bdcb")));
    pool_index_map_.insert(std::make_pair(88, common::Encode::HexDecode("e73023ebb96db49d53597f199857a23f3d48eca7")));
    pool_index_map_.insert(std::make_pair(89, common::Encode::HexDecode("6b09b3238f5e22b652e1c017cc7d14697cb39437")));
    pool_index_map_.insert(std::make_pair(90, common::Encode::HexDecode("fc4a6ed93a98ae93f57c12423033e1d896c24a9d")));
    pool_index_map_.insert(std::make_pair(91, common::Encode::HexDecode("13bb44dc094a71a8feabd8ae7360c7a2b34a9c6e")));
    pool_index_map_.insert(std::make_pair(92, common::Encode::HexDecode("5fee474f097314509d77c9753b6683c6008763bb")));
    pool_index_map_.insert(std::make_pair(93, common::Encode::HexDecode("ab6bcb99cb13292ca34fcf73c040f22d0ef1ae3e")));
    pool_index_map_.insert(std::make_pair(94, common::Encode::HexDecode("b9eb983af01c3fd1878a2ba5d774088b1e556f7d")));
    pool_index_map_.insert(std::make_pair(95, common::Encode::HexDecode("d062998669413514ac01314bdb85159251d5da58")));
    pool_index_map_.insert(std::make_pair(96, common::Encode::HexDecode("eab8b629dbf783361df06d01e69d48511df1d8af")));
    pool_index_map_.insert(std::make_pair(97, common::Encode::HexDecode("256658ac0d48ed62a5d968ba21d5abd31792640c")));
    pool_index_map_.insert(std::make_pair(98, common::Encode::HexDecode("f9354d763991b7ef562e02e732e085aff1ab9f4e")));
    pool_index_map_.insert(std::make_pair(99, common::Encode::HexDecode("eef111d7731ad246be9503e2ddee09d43e1205ea")));
    pool_index_map_.insert(std::make_pair(100, common::Encode::HexDecode("f250f5a2977e87aab428e7e3cd441b0fd08df1d7")));
    pool_index_map_.insert(std::make_pair(101, common::Encode::HexDecode("d3c6833ca70743ee69afce370ecded48861cd823")));
    pool_index_map_.insert(std::make_pair(102, common::Encode::HexDecode("94f690a127231644b354b1f791f9c45cd805a26c")));
    pool_index_map_.insert(std::make_pair(103, common::Encode::HexDecode("0c8f9df96d9ce53ada8d4871264ff435028f4a32")));
    pool_index_map_.insert(std::make_pair(104, common::Encode::HexDecode("742a1dab8e36f816ede452c4ef9a9edbabc8fbc4")));
    pool_index_map_.insert(std::make_pair(105, common::Encode::HexDecode("c48088b66881b1d66058d067ff9f881e50bcb319")));
    pool_index_map_.insert(std::make_pair(106, common::Encode::HexDecode("e8d95fcfa6b1c5373addfaa62de09fe237fa5919")));
    pool_index_map_.insert(std::make_pair(107, common::Encode::HexDecode("3deee51bc89f6942413084f90cd2c69dc8b8cf5a")));
    pool_index_map_.insert(std::make_pair(108, common::Encode::HexDecode("e99f9a9537a0c0e3a4c9dcc7c6edba350a60e251")));
    pool_index_map_.insert(std::make_pair(109, common::Encode::HexDecode("ba0e2d9aafe3f58bd37d2cf3326e4eede220a957")));
    pool_index_map_.insert(std::make_pair(110, common::Encode::HexDecode("835116520a92148fa6c3b6b945fb9b3d3021c2eb")));
    pool_index_map_.insert(std::make_pair(111, common::Encode::HexDecode("15a8987a82ee8d7a2157b0373acc0869a0692607")));
    pool_index_map_.insert(std::make_pair(112, common::Encode::HexDecode("05f9afa1bbbb84bd8d6ef3def0b697fc5d67dfba")));
    pool_index_map_.insert(std::make_pair(113, common::Encode::HexDecode("190d13d7fb83312f95577eadfdb7b72ced868bb1")));
    pool_index_map_.insert(std::make_pair(114, common::Encode::HexDecode("40cb422123a670a44b8e90bf7cb509dcbe9e327c")));
    pool_index_map_.insert(std::make_pair(115, common::Encode::HexDecode("2dc0823dac54492963e14e093d8419454f2ab645")));
    pool_index_map_.insert(std::make_pair(116, common::Encode::HexDecode("aa34a5ca80afa0c0847a2a4a1e5969880a52579c")));
    pool_index_map_.insert(std::make_pair(117, common::Encode::HexDecode("f2f864e10dbe15371ebc303d0d5adc05a6853cef")));
    pool_index_map_.insert(std::make_pair(118, common::Encode::HexDecode("d6e27b60def8465b4ad9e20141f6567d946b4096")));
    pool_index_map_.insert(std::make_pair(119, common::Encode::HexDecode("e5d666860ae5d4189581a2b540e206b785b4738f")));
    pool_index_map_.insert(std::make_pair(120, common::Encode::HexDecode("6c9bfacbe49d1fc0cb6bbea553e3949822be7ac8")));
    pool_index_map_.insert(std::make_pair(121, common::Encode::HexDecode("00995aa5da66c52065d7e7176b150a2014249824")));
    pool_index_map_.insert(std::make_pair(122, common::Encode::HexDecode("7d3a355fa6c35fde7e0f57166fe2708d4d94f1c9")));
    pool_index_map_.insert(std::make_pair(123, common::Encode::HexDecode("9251a032f5f65016eada0d34ee828f142bb67fb8")));
    pool_index_map_.insert(std::make_pair(124, common::Encode::HexDecode("c95125ecbaf656181405b635185a833502ac96a1")));
    pool_index_map_.insert(std::make_pair(125, common::Encode::HexDecode("72f16d63f743c3e6a58bda9c1b20d2ff4d96d37b")));
    pool_index_map_.insert(std::make_pair(126, common::Encode::HexDecode("cfbe02ac9035253abe69ed1a2fd10e60ccde4dc2")));
    pool_index_map_.insert(std::make_pair(127, common::Encode::HexDecode("da709470dec3cfc9cc8d86973b813f6fcb9f4be0")));
    pool_index_map_.insert(std::make_pair(128, common::Encode::HexDecode("d37581e194696e08fa541e6fc83a621758d19b39")));
    pool_index_map_.insert(std::make_pair(129, common::Encode::HexDecode("5fc398837fcdfdf4a55f3df5399ef85709169925")));
    pool_index_map_.insert(std::make_pair(130, common::Encode::HexDecode("c4e603c58e8770886d76d351d697b3bb3091f0fa")));
    pool_index_map_.insert(std::make_pair(131, common::Encode::HexDecode("26affca531ffac4dd29c952dc8acbe0675d4005f")));
    pool_index_map_.insert(std::make_pair(132, common::Encode::HexDecode("79ed311f7a2d60c6d52b620dd6c4622e9f23766a")));
    pool_index_map_.insert(std::make_pair(133, common::Encode::HexDecode("7b36bf3da016661d045f650194f71da0c5c6a30e")));
    pool_index_map_.insert(std::make_pair(134, common::Encode::HexDecode("0d09a08525f759e04b066b9b9ac0fdedfd08b760")));
    pool_index_map_.insert(std::make_pair(135, common::Encode::HexDecode("b3f246f4a502451cbc156f45f7250c1f7cdb12f0")));
    pool_index_map_.insert(std::make_pair(136, common::Encode::HexDecode("d887131cc8fee6ab981bea7079e0b1bd43b33693")));
    pool_index_map_.insert(std::make_pair(137, common::Encode::HexDecode("92fb4a0ad77a833de765c919234419f36b477618")));
    pool_index_map_.insert(std::make_pair(138, common::Encode::HexDecode("54af4b0cd19a32a7b70386a29ac5653d6bd20be9")));
    pool_index_map_.insert(std::make_pair(139, common::Encode::HexDecode("3d3fb765c64f5a07211df0bce6dd979c58a34a24")));
    pool_index_map_.insert(std::make_pair(140, common::Encode::HexDecode("b168170bf828e7aa8e59ae9aadc376110988224a")));
    pool_index_map_.insert(std::make_pair(141, common::Encode::HexDecode("0cb051f28d865a1d66032b71fc6d29f83566d185")));
    pool_index_map_.insert(std::make_pair(142, common::Encode::HexDecode("c51ea51dae1b75e54dcb598f2592b10bafe351dd")));
    pool_index_map_.insert(std::make_pair(143, common::Encode::HexDecode("a2ce2252ab4a59d9a4eec6955a1a6dc2ae77622e")));
    pool_index_map_.insert(std::make_pair(144, common::Encode::HexDecode("52857d9f92b1d2ef932c3be9218200986f3fb079")));
    pool_index_map_.insert(std::make_pair(145, common::Encode::HexDecode("1bd057320e9e6fa0c398b6fff9e9f14f63b2014c")));
    pool_index_map_.insert(std::make_pair(146, common::Encode::HexDecode("4ac10ca85fbcaad7e238755e3348ffe36145f5ed")));
    pool_index_map_.insert(std::make_pair(147, common::Encode::HexDecode("cb99a353942ce13b8d86ac07f8c05ff33ef9d7cf")));
    pool_index_map_.insert(std::make_pair(148, common::Encode::HexDecode("e07e90d0e7c1f130b0787045d9d35d5584b905df")));
    pool_index_map_.insert(std::make_pair(149, common::Encode::HexDecode("4f8d9b6d3e7ba9f36901f2a282a9c9de47b535c2")));
    pool_index_map_.insert(std::make_pair(150, common::Encode::HexDecode("0e23cca014a8ec410a80e2d019ff24167f6a302f")));
    pool_index_map_.insert(std::make_pair(151, common::Encode::HexDecode("fa59c2f91202a721761c4e8e4b1747bb91e36752")));
    pool_index_map_.insert(std::make_pair(152, common::Encode::HexDecode("3321810f83ed2ae9dcb6140e2e32dbf8f93a2573")));
    pool_index_map_.insert(std::make_pair(153, common::Encode::HexDecode("5dbaf6663ee9b64d4425a9c830b3989f500d6ba9")));
    pool_index_map_.insert(std::make_pair(154, common::Encode::HexDecode("99a745078891dcaf951e366751704b29477fbcd2")));
    pool_index_map_.insert(std::make_pair(155, common::Encode::HexDecode("60009b13de5d1009766086587613c86e366a7ac0")));
    pool_index_map_.insert(std::make_pair(156, common::Encode::HexDecode("ca39a921cfc2e2f99765219e42f24ffa0a079447")));
    pool_index_map_.insert(std::make_pair(157, common::Encode::HexDecode("add22441d1be56e3598193ed2501f6aa363a53de")));
    pool_index_map_.insert(std::make_pair(158, common::Encode::HexDecode("485a71c4ee828331f00ecd4d2b146236bd5cc5a4")));
    pool_index_map_.insert(std::make_pair(159, common::Encode::HexDecode("824f96615273d0ca677163e6074f8e3445a52ada")));
    pool_index_map_.insert(std::make_pair(160, common::Encode::HexDecode("5086427b6c89b3466adbef933a02112402ac6eb5")));
    pool_index_map_.insert(std::make_pair(161, common::Encode::HexDecode("134d395336d5681e046c4628ebe3566acb693392")));
    pool_index_map_.insert(std::make_pair(162, common::Encode::HexDecode("ac8bfb83bb45728974e704d3eda9dd86a77e4db8")));
    pool_index_map_.insert(std::make_pair(163, common::Encode::HexDecode("1a9d4af2d3d7b1bad194515d17a1ccc6703147fa")));
    pool_index_map_.insert(std::make_pair(164, common::Encode::HexDecode("91920d805294f5371001fcb544b97c7756dcc6b6")));
    pool_index_map_.insert(std::make_pair(165, common::Encode::HexDecode("6ea314bb4279eb336c5fadabb43816917d1298bd")));
    pool_index_map_.insert(std::make_pair(166, common::Encode::HexDecode("b0e0bae7b0b117a2fb5f3693e7b51ec993e222f6")));
    pool_index_map_.insert(std::make_pair(167, common::Encode::HexDecode("5340aa3d0ebd936b38127896f9452f432dc1e97b")));
    pool_index_map_.insert(std::make_pair(168, common::Encode::HexDecode("ad07967985bcfd45670951f0ce790ba670ff45ef")));
    pool_index_map_.insert(std::make_pair(169, common::Encode::HexDecode("f920479b763af3efb19ba5a8a92eb768fea956ad")));
    pool_index_map_.insert(std::make_pair(170, common::Encode::HexDecode("3c611bef178785783301915b878d5c76c95df6db")));
    pool_index_map_.insert(std::make_pair(171, common::Encode::HexDecode("4939b5d239c2c464ee618f5708069cb0ad9c800e")));
    pool_index_map_.insert(std::make_pair(172, common::Encode::HexDecode("177ba041eb2cc73d3bd3aae648144d0ec92eab58")));
    pool_index_map_.insert(std::make_pair(173, common::Encode::HexDecode("9c58cfffa046149097b3ae0c3233346a39b1b75e")));
    pool_index_map_.insert(std::make_pair(174, common::Encode::HexDecode("6e9bcb5e78d25716de15d58879d14aaa2694cae2")));
    pool_index_map_.insert(std::make_pair(175, common::Encode::HexDecode("0ff64c61a97b13a90c80fd0fd2d2d99f06550f27")));
    pool_index_map_.insert(std::make_pair(176, common::Encode::HexDecode("477726a05f333d097594e185dd06caacb36d6c79")));
    pool_index_map_.insert(std::make_pair(177, common::Encode::HexDecode("a5ae691e17020e8c5579cb49b1d062bc1a196165")));
    pool_index_map_.insert(std::make_pair(178, common::Encode::HexDecode("b5b0756a791aaf421384f88cc344951e73b17fc9")));
    pool_index_map_.insert(std::make_pair(179, common::Encode::HexDecode("1133785070cde0aabcb84dd01e40a7636f38a30f")));
    pool_index_map_.insert(std::make_pair(180, common::Encode::HexDecode("43b30d3d8926e19f2db0800921460f3d6484dfcc")));
    pool_index_map_.insert(std::make_pair(181, common::Encode::HexDecode("63c53e3cd851883ce4cd3bf2b4e9476311d2d345")));
    pool_index_map_.insert(std::make_pair(182, common::Encode::HexDecode("06d27861eb44b355fc23d730e74e258c63f147ab")));
    pool_index_map_.insert(std::make_pair(183, common::Encode::HexDecode("08e76ded2ce13eccd92f3f9f16d55b1fe4fdd81b")));
    pool_index_map_.insert(std::make_pair(184, common::Encode::HexDecode("35bb50d870461533f4b153e5d30f8151be3cc5dd")));
    pool_index_map_.insert(std::make_pair(185, common::Encode::HexDecode("9e2357484715f1e144c6905f8985bc663eadd74f")));
    pool_index_map_.insert(std::make_pair(186, common::Encode::HexDecode("7f69b8f01be1c63ff1b9124b579a95a561d9d449")));
    pool_index_map_.insert(std::make_pair(187, common::Encode::HexDecode("f619e402d04ad40c7e0a38964fd09249716d0f83")));
    pool_index_map_.insert(std::make_pair(188, common::Encode::HexDecode("9d7b1ef774b890f2690b95e49d4f07fbb60e27d3")));
    pool_index_map_.insert(std::make_pair(189, common::Encode::HexDecode("8bca29c6e537765f9a6b0462430d6e91fe687675")));
    pool_index_map_.insert(std::make_pair(190, common::Encode::HexDecode("ee6322edfabf3bde54dcf4af78f3cd72c3490bd1")));
    pool_index_map_.insert(std::make_pair(191, common::Encode::HexDecode("0171cbdb83e303671cfaa1b7af38a4522a662796")));
    pool_index_map_.insert(std::make_pair(192, common::Encode::HexDecode("0b5e74abbffe6c5e1165ce552bdd6ca9497f43a3")));
    pool_index_map_.insert(std::make_pair(193, common::Encode::HexDecode("e32dbcfc64adee6071eee7b2cb303355f203a65e")));
    pool_index_map_.insert(std::make_pair(194, common::Encode::HexDecode("693c0b850be0d5d1e62aadeba8013d8a5681572e")));
    pool_index_map_.insert(std::make_pair(195, common::Encode::HexDecode("967f5dc37384dd87ab5b7dcc3d0e388935902ace")));
    pool_index_map_.insert(std::make_pair(196, common::Encode::HexDecode("12eb25858c163ae0f5f021abd1e926af25c7f0ab")));
    pool_index_map_.insert(std::make_pair(197, common::Encode::HexDecode("e787c5303c9203e2ddec1c796d0a221d42ad27a8")));
    pool_index_map_.insert(std::make_pair(198, common::Encode::HexDecode("8f21eb951901ac57961271caa50c67c8987ed795")));
    pool_index_map_.insert(std::make_pair(199, common::Encode::HexDecode("d0b8fd2b22c87b1dcc1739fe2e341a8914c841ca")));
    pool_index_map_.insert(std::make_pair(200, common::Encode::HexDecode("4c119c16685f3c69d687ced123bb044705c400dd")));
    pool_index_map_.insert(std::make_pair(201, common::Encode::HexDecode("3f3a0ba99810ca2a7ae67a3e24b047fc9a66d276")));
    pool_index_map_.insert(std::make_pair(202, common::Encode::HexDecode("eb4ca44b1fec8099f26e656602fa0c7e01182ecf")));
    pool_index_map_.insert(std::make_pair(203, common::Encode::HexDecode("9a01db4c78d99733141f306bdc55bdb5ff6a2687")));
    pool_index_map_.insert(std::make_pair(204, common::Encode::HexDecode("0a4fef2571d94f5a9a2fbb883a9a4fa1a3a9d320")));
    pool_index_map_.insert(std::make_pair(205, common::Encode::HexDecode("ad014631eb38a4ceb37a1c9225e0e00c3766fa03")));
    pool_index_map_.insert(std::make_pair(206, common::Encode::HexDecode("31c847f1468a214375754113fa5ecaa92cffff21")));
    pool_index_map_.insert(std::make_pair(207, common::Encode::HexDecode("b23b9e5aa8a74048ccee961b33fe6ca452bdae96")));
    pool_index_map_.insert(std::make_pair(208, common::Encode::HexDecode("9a7006d5a501c1b78936361e1bacff019e3051f6")));
    pool_index_map_.insert(std::make_pair(209, common::Encode::HexDecode("2264cf297ac9f927a861a435d37c4757906cac99")));
    pool_index_map_.insert(std::make_pair(210, common::Encode::HexDecode("b07dec79b7de14af7958fdd92ad1e4c287310a0c")));
    pool_index_map_.insert(std::make_pair(211, common::Encode::HexDecode("c397fabca97587f5a24535dbc3d421c6f54757f1")));
    pool_index_map_.insert(std::make_pair(212, common::Encode::HexDecode("836b6903b64dcacb53a10e82318fbd6ef452d673")));
    pool_index_map_.insert(std::make_pair(213, common::Encode::HexDecode("562a920cc0f1e05b2046cd8365831a8d3426482a")));
    pool_index_map_.insert(std::make_pair(214, common::Encode::HexDecode("51df3c30c09c2912d2dd3c5369673fadc6c16d4f")));
    pool_index_map_.insert(std::make_pair(215, common::Encode::HexDecode("7a63ffa29c9baf671907311929ceb6f0ac00bb01")));
    pool_index_map_.insert(std::make_pair(216, common::Encode::HexDecode("e17c3ea052634983278db165aa8c9964a466130d")));
    pool_index_map_.insert(std::make_pair(217, common::Encode::HexDecode("3a8d63ace755ec666c8f61c4536c4b4fc05d0542")));
    pool_index_map_.insert(std::make_pair(218, common::Encode::HexDecode("cc10b5dd27e2a5aeb9bee239f1f0687dcd0c0f67")));
    pool_index_map_.insert(std::make_pair(219, common::Encode::HexDecode("cf3cdbc2c39d3f0c3db472ec2492183ad4f22243")));
    pool_index_map_.insert(std::make_pair(220, common::Encode::HexDecode("1a5508a4be5a2c31c050947eff508a36f6953195")));
    pool_index_map_.insert(std::make_pair(221, common::Encode::HexDecode("86c77ffbeb2e6ef16659ace4fdaaa484db7e7e04")));
    pool_index_map_.insert(std::make_pair(222, common::Encode::HexDecode("ff680c3965310b97e1ac5ae11683a1f46f58fdd3")));
    pool_index_map_.insert(std::make_pair(223, common::Encode::HexDecode("35fee6714a4a6495d7b2600443a897636821f500")));
    pool_index_map_.insert(std::make_pair(224, common::Encode::HexDecode("b0e86db94c4ac4ed703596c7c34044aa97470fba")));
    pool_index_map_.insert(std::make_pair(225, common::Encode::HexDecode("91715e00fe4d608c52c99cdf2b7cadce2a8d5679")));
    pool_index_map_.insert(std::make_pair(226, common::Encode::HexDecode("46b82ef6407a01b1853deac6d323e925aac8c24e")));
    pool_index_map_.insert(std::make_pair(227, common::Encode::HexDecode("0e18db5fc28c5e5a02f6aee006debac74e9b0806")));
    pool_index_map_.insert(std::make_pair(228, common::Encode::HexDecode("c0033742cb50fdc59a1adc69c9c81bce3e9e1247")));
    pool_index_map_.insert(std::make_pair(229, common::Encode::HexDecode("baf14b6efd3d695bb37295fa4b41064d834fb995")));
    pool_index_map_.insert(std::make_pair(230, common::Encode::HexDecode("b2a4c26d0835c153e960e720966c87e827761f63")));
    pool_index_map_.insert(std::make_pair(231, common::Encode::HexDecode("b0e2c1bb33f79390dc8d8f528888de95f92acea9")));
    pool_index_map_.insert(std::make_pair(232, common::Encode::HexDecode("869ef0e1098c602ca1f979a91c8ccf657301ff98")));
    pool_index_map_.insert(std::make_pair(233, common::Encode::HexDecode("ec583dbf4d5cb100878cf179e6f658070e8a846e")));
    pool_index_map_.insert(std::make_pair(234, common::Encode::HexDecode("2ce34a222731e9d7686bb220e8f29f04f4572d34")));
    pool_index_map_.insert(std::make_pair(235, common::Encode::HexDecode("4c16f44f03c46620d6bb4d7e75bbe5b727830fcd")));
    pool_index_map_.insert(std::make_pair(236, common::Encode::HexDecode("c87c41ceb3e5bf005743371b0a7cdb56836006cf")));
    pool_index_map_.insert(std::make_pair(237, common::Encode::HexDecode("11e16b98e9081ba96ce2e184457a25350519f3a0")));
    pool_index_map_.insert(std::make_pair(238, common::Encode::HexDecode("51678b6fdc1c76ee6e06a1fc266f2dff7e0594b4")));
    pool_index_map_.insert(std::make_pair(239, common::Encode::HexDecode("c0b6f2cca477d437fc3d5cdc06b8a114e20419d8")));
    pool_index_map_.insert(std::make_pair(240, common::Encode::HexDecode("532274cd40fdd3981fa9449a5ad4941c7c2675f5")));
    pool_index_map_.insert(std::make_pair(241, common::Encode::HexDecode("d9ac61c734e4cf192b16e6d0b6f3c768d1d53b3a")));
    pool_index_map_.insert(std::make_pair(242, common::Encode::HexDecode("d6c590a5e8b11e0274d97bd7aa94acab014f2758")));
    pool_index_map_.insert(std::make_pair(243, common::Encode::HexDecode("788e05536bd00818cad9df41ef6e7e706d62f5a2")));
    pool_index_map_.insert(std::make_pair(244, common::Encode::HexDecode("3914045c82d88f17188b539a6f8e86771307810a")));
    pool_index_map_.insert(std::make_pair(245, common::Encode::HexDecode("832c48c78c5d56a06fa462967ae91d8d86bc06f9")));
    pool_index_map_.insert(std::make_pair(246, common::Encode::HexDecode("f6b84ef824799dd400a0ed3011fb027573662a50")));
    pool_index_map_.insert(std::make_pair(247, common::Encode::HexDecode("daf42a34b92d0cf464199e5f4ebcdcedb7ea529b")));
    pool_index_map_.insert(std::make_pair(248, common::Encode::HexDecode("a767629de963006bc5aded37969a9aa57e084835")));
    pool_index_map_.insert(std::make_pair(249, common::Encode::HexDecode("d7179560bb9d78ad9ba94f0f940121f3e98c7339")));
    pool_index_map_.insert(std::make_pair(250, common::Encode::HexDecode("4d0f3ecfd46bfd2cbbbc6db048c0b235d332835e")));
    pool_index_map_.insert(std::make_pair(251, common::Encode::HexDecode("0275c0b964e9677efa83365bf67cb4e6c064d379")));
    pool_index_map_.insert(std::make_pair(252, common::Encode::HexDecode("c688d769c71aa91ef22f1ad716be5a0ffce0935f")));
    pool_index_map_.insert(std::make_pair(253, common::Encode::HexDecode("eb2966d5a5644ab891f950656fbf6662c5828943")));
    pool_index_map_.insert(std::make_pair(254, common::Encode::HexDecode("92b1b06f422793b49826100ea4896499536fa09b")));
    pool_index_map_.insert(std::make_pair(255, common::Encode::HexDecode("5a5232ae1648d2e50f3c677a991df5c5d24cf6a8")));
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
