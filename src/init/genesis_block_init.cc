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
        return CreateRootGenesisBlocks();
    }

    return CreateShardGenesisBlocks(net_id);
}

int GenesisBlockInit::CreateRootGenesisBlocks() {
    GenerateRootAccounts();
    uint64_t genesis_account_balance = 0llu;
    uint64_t all_balance = 0llu;
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        auto iter = root_account_with_pool_index_map_.find(i);
        std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(iter->second);
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
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != genesis_account_balance) {
            return kInitError;
        }

        all_balance += balance;
    }

    if (all_balance != common::kGenesisFoundationMaxTenon) {
        return kInitError;
    }

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
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
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
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance), block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != 0) {
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
        tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(1, now_tm);
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
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
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != 0) {
            return kInitError;
        }
    }

    return kInitSuccess;
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
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != genesis_account_balance) {
            return kInitError;
        }

        all_balance += balance;
    }

    if (all_balance != common::kGenesisFoundationMaxTenon) {
        return kInitError;
    }

    return kInitSuccess;
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
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        root_account_with_pool_index_map_.insert(std::make_pair(
            i,
            common::Encode::HexDecode(common::StringUtil::Format(
                "1000000000000000000000000000000000000%3d", i))));
    }
}

};  // namespace init

};  // namespace tenon
