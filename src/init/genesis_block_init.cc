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
        security::PrivateKey prikey(iter->second);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        if (pubkey.Serialize(pubkey_str, false) != security::kPublicKeyUncompressSize) {
            return kInitError;
        }

        std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        auto tx_info = tx_list->Add();
        tx_info->set_version(common::kTransactionVersion);
        tx_info->set_gid(common::CreateGID(""));
        tx_info->set_from(address);
        tx_info->set_from_pubkey(pubkey_str);
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
    pool_index_map_.insert(std::make_pair(255, common::Encode::HexDecode("c6945f19bf4b5c1db6ff312a683f08e9c0c94b5b")));
    pool_index_map_.insert(std::make_pair(254, common::Encode::HexDecode("c7cd9c5f9e9913617ca0e0eced92a2e076a2538b")));
    pool_index_map_.insert(std::make_pair(253, common::Encode::HexDecode("2fbabc40fd7dcff37eab8d57fb08d93d55d62a1a")));
    pool_index_map_.insert(std::make_pair(252, common::Encode::HexDecode("e6908f7eab4abcf450facdef1684e3b56b61703f")));
    pool_index_map_.insert(std::make_pair(251, common::Encode::HexDecode("3993011ae4f60aa1edfd5e06ea382cca2562f5e7")));
    pool_index_map_.insert(std::make_pair(250, common::Encode::HexDecode("03b5de0d0cebde1242c7ed55c8e2f4a81d3862c4")));
    pool_index_map_.insert(std::make_pair(249, common::Encode::HexDecode("76f40fee86c660145ff4e6dad2b4e94568db26d4")));
    pool_index_map_.insert(std::make_pair(248, common::Encode::HexDecode("f2d9111de1dfd1016416342c2a6bd5c4e9157480")));
    pool_index_map_.insert(std::make_pair(247, common::Encode::HexDecode("a1210d160cea014d186887e0dfb3fd0570da7651")));
    pool_index_map_.insert(std::make_pair(246, common::Encode::HexDecode("4fc592e5bf7974c74d4772c538637dd393f1050f")));
    pool_index_map_.insert(std::make_pair(245, common::Encode::HexDecode("6bd3dc22e8fd5d0befa241a651f0f3e5bfd74609")));
    pool_index_map_.insert(std::make_pair(244, common::Encode::HexDecode("152921319df428049a2c3c0f727b69451385c280")));
    pool_index_map_.insert(std::make_pair(243, common::Encode::HexDecode("92dac662fa9f8c50ed6355e22208c92544068dd1")));
    pool_index_map_.insert(std::make_pair(242, common::Encode::HexDecode("ba23071a760c21212d77283d185cf6318222f6d0")));
    pool_index_map_.insert(std::make_pair(241, common::Encode::HexDecode("112a4d37d26f7a2f368aa933a1d470c7fd96340c")));
    pool_index_map_.insert(std::make_pair(240, common::Encode::HexDecode("5f4e1b084a54bf3bda60a9183d1f309e1db960a5")));
    pool_index_map_.insert(std::make_pair(239, common::Encode::HexDecode("dd2f75edf32b66913183af339c6900c7eb6e6e1b")));
    pool_index_map_.insert(std::make_pair(238, common::Encode::HexDecode("0a5c93628fd8df0a96a5a53343c09b4f699eccad")));
    pool_index_map_.insert(std::make_pair(237, common::Encode::HexDecode("a4a79e4c2a6bd75c3982870e78a8b7652bd0a5c7")));
    pool_index_map_.insert(std::make_pair(236, common::Encode::HexDecode("58b3804ce2ccc170fadedfab04953f3292d3327e")));
    pool_index_map_.insert(std::make_pair(235, common::Encode::HexDecode("9eae242661e68c17b95622f06579a7a43ce203fd")));
    pool_index_map_.insert(std::make_pair(234, common::Encode::HexDecode("4802874416253a5976e4aeb277db8cfc8011edb9")));
    pool_index_map_.insert(std::make_pair(233, common::Encode::HexDecode("6ec22a1a94d7fe9ae4caa925686377346ba04256")));
    pool_index_map_.insert(std::make_pair(232, common::Encode::HexDecode("2de933b0ebb0efdc1a3653dd824a791bbfa8df63")));
    pool_index_map_.insert(std::make_pair(231, common::Encode::HexDecode("58042325a095963f8dd1f93256d3e39958c1f6c6")));
    pool_index_map_.insert(std::make_pair(230, common::Encode::HexDecode("6b115a86f3f28a13f40818c1355b2aa8a9924ecc")));
    pool_index_map_.insert(std::make_pair(229, common::Encode::HexDecode("fd95ea2a81b58504d7eeb753311cef05887236c6")));
    pool_index_map_.insert(std::make_pair(228, common::Encode::HexDecode("dffa6cce9340f316f62332bab3c2fe897f863ee4")));
    pool_index_map_.insert(std::make_pair(227, common::Encode::HexDecode("4435a7f9750b2b68f3187d627ee3725354d82251")));
    pool_index_map_.insert(std::make_pair(226, common::Encode::HexDecode("23ae6a2ff7b3fe1c4cac5d103df117c1846df806")));
    pool_index_map_.insert(std::make_pair(225, common::Encode::HexDecode("a1db667c69d6013301188b5270e6c4ad1b8b012f")));
    pool_index_map_.insert(std::make_pair(224, common::Encode::HexDecode("0eeb107c2fa8c9d70132e0bc6b576f6e7f9d8eb0")));
    pool_index_map_.insert(std::make_pair(223, common::Encode::HexDecode("a418c63747e46279bacf1ad581221d29f502ebf8")));
    pool_index_map_.insert(std::make_pair(222, common::Encode::HexDecode("4f1e0b19a48c571cfc078762347f5a514ccad583")));
    pool_index_map_.insert(std::make_pair(221, common::Encode::HexDecode("22bb9355d32ac566c6318f0e032569f54129eb34")));
    pool_index_map_.insert(std::make_pair(220, common::Encode::HexDecode("12313a821f1213f74fb2ec3771dc8e1bda08d33c")));
    pool_index_map_.insert(std::make_pair(219, common::Encode::HexDecode("99be8642a98703f50885a2b5d054f984ab0f48ec")));
    pool_index_map_.insert(std::make_pair(218, common::Encode::HexDecode("987070047a8d4df6241cade7adb6117dc3294b98")));
    pool_index_map_.insert(std::make_pair(217, common::Encode::HexDecode("35ba45ebe1405d54a2a4ca626fed72289870e3d9")));
    pool_index_map_.insert(std::make_pair(216, common::Encode::HexDecode("dc174f7d83506b27c186dd96753ceb46e5f3ed56")));
    pool_index_map_.insert(std::make_pair(215, common::Encode::HexDecode("c0941329f7ef28dc1a00a9805e6a7ca084cacf2b")));
    pool_index_map_.insert(std::make_pair(214, common::Encode::HexDecode("2213eefc50c313c7328cada205d6e8f4b58bf484")));
    pool_index_map_.insert(std::make_pair(213, common::Encode::HexDecode("36ee9101df04a240722a65bf437da8c6958f3e97")));
    pool_index_map_.insert(std::make_pair(212, common::Encode::HexDecode("8d5d4f6a102599e3d02c434d9179aedf56a82ac2")));
    pool_index_map_.insert(std::make_pair(211, common::Encode::HexDecode("48304036f30e79bfc6282310b7dfe01665750050")));
    pool_index_map_.insert(std::make_pair(210, common::Encode::HexDecode("cf90b06df74e43125ae7f5ce587f1ddbe4bfb281")));
    pool_index_map_.insert(std::make_pair(209, common::Encode::HexDecode("b024e12da60f607570372c4c260cd26f1e96a971")));
    pool_index_map_.insert(std::make_pair(208, common::Encode::HexDecode("52e73a25c651f4a63da8af75ead17225b9d43d21")));
    pool_index_map_.insert(std::make_pair(207, common::Encode::HexDecode("bd468f7e384edd71307d37d0aa44dc3d057efff9")));
    pool_index_map_.insert(std::make_pair(206, common::Encode::HexDecode("b1905a310c7211e432d0b5bfc4e34b60a906570f")));
    pool_index_map_.insert(std::make_pair(205, common::Encode::HexDecode("5c112c1df92c9297843c682af06b76ab0c4a33cd")));
    pool_index_map_.insert(std::make_pair(204, common::Encode::HexDecode("6145729094f09dbf77e67e9a15cfc13bcf24c259")));
    pool_index_map_.insert(std::make_pair(203, common::Encode::HexDecode("5f794904f0215806a66fd467a52bf9607f7739b8")));
    pool_index_map_.insert(std::make_pair(202, common::Encode::HexDecode("a066c537d02a8d882b25f10b2933a8b60ac00c52")));
    pool_index_map_.insert(std::make_pair(201, common::Encode::HexDecode("bbbe10dc74a7bddce4903d6f3b5bac10a3029a83")));
    pool_index_map_.insert(std::make_pair(200, common::Encode::HexDecode("3c68050ad87866f8047e0a3d0cdbdd4c1c2af00f")));
    pool_index_map_.insert(std::make_pair(199, common::Encode::HexDecode("6de3eedca9c07362207a8403bf8bda78e676a8cc")));
    pool_index_map_.insert(std::make_pair(198, common::Encode::HexDecode("ab69010e9a8ebfe590ac3ddf9122c194ea4ebbfa")));
    pool_index_map_.insert(std::make_pair(197, common::Encode::HexDecode("53b13ceeae781f6ee286143e1f86af86e6b9c5c7")));
    pool_index_map_.insert(std::make_pair(196, common::Encode::HexDecode("6ba018d6a6585600555cdfa7ef3660ff24ccf541")));
    pool_index_map_.insert(std::make_pair(195, common::Encode::HexDecode("e01f9a6e3cae76abc9603144ddee0b63f5b3dafb")));
    pool_index_map_.insert(std::make_pair(194, common::Encode::HexDecode("4018f9430d14e27a6a2262106486aaed46a8a4cc")));
    pool_index_map_.insert(std::make_pair(193, common::Encode::HexDecode("35768023af5c050d752bfb3fbecc25aa9c1e1ad4")));
    pool_index_map_.insert(std::make_pair(192, common::Encode::HexDecode("d5cfedee97057bc7d021b4652e91f612a8628162")));
    pool_index_map_.insert(std::make_pair(191, common::Encode::HexDecode("5e4aa03cdb5ce838e5901353d547d27191d90547")));
    pool_index_map_.insert(std::make_pair(190, common::Encode::HexDecode("cb17deac715912cebf3e1d8b2a52a61fc70a427b")));
    pool_index_map_.insert(std::make_pair(189, common::Encode::HexDecode("e2d5971580217cba5bb29391351672c5d50a3104")));
    pool_index_map_.insert(std::make_pair(188, common::Encode::HexDecode("1607f4c5458490ce97f8103170170101f3b42f6c")));
    pool_index_map_.insert(std::make_pair(187, common::Encode::HexDecode("665eba081135beaa33c4a46ac40009a3ff94d0ad")));
    pool_index_map_.insert(std::make_pair(186, common::Encode::HexDecode("ee172c6469cdcc6ec9d14c21b873a31c67c9bbfa")));
    pool_index_map_.insert(std::make_pair(185, common::Encode::HexDecode("c11d74d6adbd2b57754b3de60d77f59301b1039e")));
    pool_index_map_.insert(std::make_pair(184, common::Encode::HexDecode("f6630300644daba56c9a7719115d45d47dbca7f7")));
    pool_index_map_.insert(std::make_pair(183, common::Encode::HexDecode("b933be2ef9d07411eee49dd02f9f71b232c0b33f")));
    pool_index_map_.insert(std::make_pair(182, common::Encode::HexDecode("5e42cc8dbdea045b2d78b5d18ed831c583e3ae50")));
    pool_index_map_.insert(std::make_pair(181, common::Encode::HexDecode("6fef463fc132c8fb72ad5f7a91ae1e2179b703ac")));
    pool_index_map_.insert(std::make_pair(180, common::Encode::HexDecode("681d30816c899ead1b0469f114cfd0bca75dd65a")));
    pool_index_map_.insert(std::make_pair(179, common::Encode::HexDecode("67e82a80e2986df49f4a8812beb58d2c28da8a5f")));
    pool_index_map_.insert(std::make_pair(178, common::Encode::HexDecode("f0d7f0ec5a35a8258126970892d3892313584ffa")));
    pool_index_map_.insert(std::make_pair(177, common::Encode::HexDecode("41cac202e146754f30168ff2df0a64c96c782854")));
    pool_index_map_.insert(std::make_pair(176, common::Encode::HexDecode("617ef662048b340279c4080201c520fa0448f69d")));
    pool_index_map_.insert(std::make_pair(175, common::Encode::HexDecode("e156c67be784135cbf7abdb38c84531091d97e25")));
    pool_index_map_.insert(std::make_pair(174, common::Encode::HexDecode("9bdd9fcd4cfe9d29fc51416d4f615647c99b311d")));
    pool_index_map_.insert(std::make_pair(173, common::Encode::HexDecode("602c6c6645f0d9382cbcb4f7ed836d0f45764c9c")));
    pool_index_map_.insert(std::make_pair(172, common::Encode::HexDecode("6d2005467914d36bcc15d932e3e8a0ba1f46eb58")));
    pool_index_map_.insert(std::make_pair(171, common::Encode::HexDecode("9c94e2673d32645c9b34af06ada101490be6ff03")));
    pool_index_map_.insert(std::make_pair(170, common::Encode::HexDecode("f0d7dc37330df808296aa7e51a8628a09d8ea1c6")));
    pool_index_map_.insert(std::make_pair(169, common::Encode::HexDecode("3b4a3e7716a830ee284adeb66f7a42e5f2c8196a")));
    pool_index_map_.insert(std::make_pair(168, common::Encode::HexDecode("d85a47a67293696d720ba3c2da08b7ddfc0828a3")));
    pool_index_map_.insert(std::make_pair(167, common::Encode::HexDecode("f9bfd742336f0065886880561909a46fdd2ff514")));
    pool_index_map_.insert(std::make_pair(166, common::Encode::HexDecode("c403206c04325a0ef66c334a19254cfdbda8d161")));
    pool_index_map_.insert(std::make_pair(77, common::Encode::HexDecode("3e61eb9057a4492a54e48fea9dd9cff95609dd93")));
    pool_index_map_.insert(std::make_pair(76, common::Encode::HexDecode("9817a5eee365903233b86ea6a7cdc8805c4989e2")));
    pool_index_map_.insert(std::make_pair(75, common::Encode::HexDecode("5b273bce6ed457c84ac8eafa78e75a55874ca589")));
    pool_index_map_.insert(std::make_pair(74, common::Encode::HexDecode("1d90066cbab12b05860d1fa6a32f0f4ed095ec99")));
    pool_index_map_.insert(std::make_pair(73, common::Encode::HexDecode("ed12fbef33288ab76c6a1e56d6996cafe3cc7ef6")));
    pool_index_map_.insert(std::make_pair(72, common::Encode::HexDecode("d88b2af07e106c6deae21d3be539dc8c376bf8e0")));
    pool_index_map_.insert(std::make_pair(71, common::Encode::HexDecode("515afa6a9df2fafb079537cd7b87868ab9d3d13d")));
    pool_index_map_.insert(std::make_pair(70, common::Encode::HexDecode("5f12f089b9c0b726ebec0e7f8da5f519a0240bed")));
    pool_index_map_.insert(std::make_pair(69, common::Encode::HexDecode("da5b1781f2cc44ddd38d50b0ff1cc1622515f1fd")));
    pool_index_map_.insert(std::make_pair(68, common::Encode::HexDecode("ca68ee9cc77f33d6c42b0252e1e152bee98fc7ce")));
    pool_index_map_.insert(std::make_pair(67, common::Encode::HexDecode("79292860b097e5c4df4c53eb5e7b620c7d100967")));
    pool_index_map_.insert(std::make_pair(66, common::Encode::HexDecode("d8de3ef8154ee6b6697b6497a834c200b1d88b91")));
    pool_index_map_.insert(std::make_pair(65, common::Encode::HexDecode("0166e669f971ffd8c915a39efb0767b982343675")));
    pool_index_map_.insert(std::make_pair(64, common::Encode::HexDecode("5db6cc9239a2bce4a7071410321da7c159d7c781")));
    pool_index_map_.insert(std::make_pair(63, common::Encode::HexDecode("941c59648eb46cbc93aeddd6b0979946d6dfb5db")));
    pool_index_map_.insert(std::make_pair(62, common::Encode::HexDecode("f37d7e261091691efdd3ca1e120bba5646a2de11")));
    pool_index_map_.insert(std::make_pair(61, common::Encode::HexDecode("2fd0b62425640e5e38b88a23499310706a79af57")));
    pool_index_map_.insert(std::make_pair(60, common::Encode::HexDecode("3471f3e42e94310e0ce7581bd9431d4ca76f039d")));
    pool_index_map_.insert(std::make_pair(59, common::Encode::HexDecode("29dd1ad97ad8a7f0c872067fcb6057b42114212f")));
    pool_index_map_.insert(std::make_pair(58, common::Encode::HexDecode("f677ca7f7012d6723b9f2f1cf3289da9f003cdd8")));
    pool_index_map_.insert(std::make_pair(57, common::Encode::HexDecode("21f8336777d4e2999d8f9b3c7e431056791cf127")));
    pool_index_map_.insert(std::make_pair(56, common::Encode::HexDecode("7b5e88452fc87e1dc93cf13450d60d1b0ce84a8b")));
    pool_index_map_.insert(std::make_pair(55, common::Encode::HexDecode("0ea6edf1b2e5a415faeff2fb449cb3eb86f7a493")));
    pool_index_map_.insert(std::make_pair(54, common::Encode::HexDecode("8a14ca48219c0199a9c9dfbc3f1770028431b2ff")));
    pool_index_map_.insert(std::make_pair(53, common::Encode::HexDecode("77ad3db664b09098d608bae26b9633cb14b5f45a")));
    pool_index_map_.insert(std::make_pair(52, common::Encode::HexDecode("253aab7f7217f0f7fe311212906e0b316ccd78ae")));
    pool_index_map_.insert(std::make_pair(51, common::Encode::HexDecode("20e6d61feb633172c35263e26f043069df4078ce")));
    pool_index_map_.insert(std::make_pair(50, common::Encode::HexDecode("1c3100f2f05e73446126858608af1ab0f1b97ed0")));
    pool_index_map_.insert(std::make_pair(49, common::Encode::HexDecode("2b7d3f5edc4a33bbc8819ec5a05492e069ef1692")));
    pool_index_map_.insert(std::make_pair(48, common::Encode::HexDecode("310c3b69e99eca156185d1c4233f9f8cc3e5ae2d")));
    pool_index_map_.insert(std::make_pair(47, common::Encode::HexDecode("5bdca5cb469889019649e15abc9feee1a95a4066")));
    pool_index_map_.insert(std::make_pair(46, common::Encode::HexDecode("cf8323dd307ee1bde047a42c5e5a64b24586791e")));
    pool_index_map_.insert(std::make_pair(45, common::Encode::HexDecode("ed1481a6cb1c881a8b6b23237559b86ff378dd62")));
    pool_index_map_.insert(std::make_pair(44, common::Encode::HexDecode("e523c3b25f1f8a38ccccd333ddd4e1c98496b762")));
    pool_index_map_.insert(std::make_pair(43, common::Encode::HexDecode("1a8410b68685cc13e1d682f6985547042bf27bb2")));
    pool_index_map_.insert(std::make_pair(42, common::Encode::HexDecode("ca5e2e22d9cfd2bdf839c9c67c45edd8318346d2")));
    pool_index_map_.insert(std::make_pair(41, common::Encode::HexDecode("fb99424249aac7fd85d33b1a24190b3419c243a3")));
    pool_index_map_.insert(std::make_pair(40, common::Encode::HexDecode("a71bf37ded20dbcd8ab7df79aa2707ba2cb1f458")));
    pool_index_map_.insert(std::make_pair(39, common::Encode::HexDecode("0d8124ad11afaf118d7d8721ffb6f7add56db9d5")));
    pool_index_map_.insert(std::make_pair(38, common::Encode::HexDecode("a7b0603d6bdc9980015e26f0ec44183a6041db66")));
    pool_index_map_.insert(std::make_pair(37, common::Encode::HexDecode("4707a90c29e27b41821afa3793d63702c4f745af")));
    pool_index_map_.insert(std::make_pair(36, common::Encode::HexDecode("a849bba517c21620a0c7574e5bf9577333ccff7d")));
    pool_index_map_.insert(std::make_pair(15, common::Encode::HexDecode("5b20974600fe5e3598884a3bbdca8a0bb3fdec4f")));
    pool_index_map_.insert(std::make_pair(14, common::Encode::HexDecode("7ef3d2ff93c60ac85b3d2e10016baaf3ef5bf1a8")));
    pool_index_map_.insert(std::make_pair(13, common::Encode::HexDecode("71217029867c4ed1ecaf3994c67c6bafed262819")));
    pool_index_map_.insert(std::make_pair(12, common::Encode::HexDecode("5d7d7464951494a59d3d6ab093718c8f79232c65")));
    pool_index_map_.insert(std::make_pair(11, common::Encode::HexDecode("37f80f3f74ef53e7b29c7d4fd6036ff6a77224fb")));
    pool_index_map_.insert(std::make_pair(10, common::Encode::HexDecode("129f12f41cc3f7448ddd58a661e605b1c46251d6")));
    pool_index_map_.insert(std::make_pair(9, common::Encode::HexDecode("ae04a51ee05667ade89ca0a1620e5dbd534039bb")));
    pool_index_map_.insert(std::make_pair(8, common::Encode::HexDecode("b53b1e1909dfcb12abc1c76c738590a51dc63835")));
    pool_index_map_.insert(std::make_pair(7, common::Encode::HexDecode("851a7a5e3aedcaf85d4cef6e96840d0e45832d35")));
    pool_index_map_.insert(std::make_pair(6, common::Encode::HexDecode("9dccb98d88f1f0333b12d67b8b353c7cd03f2b8d")));
    pool_index_map_.insert(std::make_pair(1, common::Encode::HexDecode("f83506c1d08dde6adaf7cf1bb6182a44d76fbd31")));
    pool_index_map_.insert(std::make_pair(0, common::Encode::HexDecode("9a435763577f0dc935f07d83bc478704c30e4272")));
    pool_index_map_.insert(std::make_pair(2, common::Encode::HexDecode("133dc28149e15aa121f4c9c325af12cc9a84fa7f")));
    pool_index_map_.insert(std::make_pair(3, common::Encode::HexDecode("b340eaf9af140bf62a41cd21d34431b0ee6fa15c")));
    pool_index_map_.insert(std::make_pair(4, common::Encode::HexDecode("b93a42b2e1064dcbd82eeb6078d6ad66bfef0291")));
    pool_index_map_.insert(std::make_pair(5, common::Encode::HexDecode("e970ed55166747c5d560b7fa6512871a3a7df6fc")));
    pool_index_map_.insert(std::make_pair(16, common::Encode::HexDecode("ce0a8ea9ee6dbcb51434044eec65e79370d206ab")));
    pool_index_map_.insert(std::make_pair(17, common::Encode::HexDecode("b194dbd8ea3a3ab94aa87c506cc991c3b4180b40")));
    pool_index_map_.insert(std::make_pair(18, common::Encode::HexDecode("a6653b00714dd2c4d2409a0c292ba9d5f2d59b62")));
    pool_index_map_.insert(std::make_pair(19, common::Encode::HexDecode("5a9aa7bbe10d6f18bc9ffb520dff1cb428c9e6ff")));
    pool_index_map_.insert(std::make_pair(20, common::Encode::HexDecode("d0f11766cd311421ab078e5fc97b4fdbb28e1e9f")));
    pool_index_map_.insert(std::make_pair(21, common::Encode::HexDecode("2b4d795c7260cd584a225f0e678aeffb3aa678bf")));
    pool_index_map_.insert(std::make_pair(22, common::Encode::HexDecode("3f9d0f257023c8749b32e8eb6586e9a663a4fd6c")));
    pool_index_map_.insert(std::make_pair(23, common::Encode::HexDecode("242f8a7fb42998d3d3daaf20505b02ac7aed3847")));
    pool_index_map_.insert(std::make_pair(24, common::Encode::HexDecode("2e036e3973b7e70c02f3fd53a635938a6629b149")));
    pool_index_map_.insert(std::make_pair(25, common::Encode::HexDecode("63fb662a7cc9f7cd113a44cf06f0b17e6721abd8")));
    pool_index_map_.insert(std::make_pair(26, common::Encode::HexDecode("05b3b8de1c906b5ae7fe7f3109f799f53de74c74")));
    pool_index_map_.insert(std::make_pair(27, common::Encode::HexDecode("3aa6f54e2d6ba01212ea318d9160398fdc13dc5a")));
    pool_index_map_.insert(std::make_pair(28, common::Encode::HexDecode("5fcac8ca1410b9f5c31445586d535989dfa3fb80")));
    pool_index_map_.insert(std::make_pair(29, common::Encode::HexDecode("1db64bc4c6c84d67c657e0b75d1c9242524f3fe4")));
    pool_index_map_.insert(std::make_pair(30, common::Encode::HexDecode("222cfd5ea0492e5a7583e83e406a6ada92dd53f8")));
    pool_index_map_.insert(std::make_pair(31, common::Encode::HexDecode("9b41472caa9d4c7f2516ccb46d5522891d66ebbf")));
    pool_index_map_.insert(std::make_pair(32, common::Encode::HexDecode("0b3b1a9dbb56bc6c24b5d7896a18aeba888e3e0b")));
    pool_index_map_.insert(std::make_pair(33, common::Encode::HexDecode("fe27b397398504e3f70a483e254c17623398a061")));
    pool_index_map_.insert(std::make_pair(34, common::Encode::HexDecode("bcdf2117bd05520547b18c16af8c6e18a05d589e")));
    pool_index_map_.insert(std::make_pair(35, common::Encode::HexDecode("30b17befeeb650ece069dc3d802756bae532b51b")));
    pool_index_map_.insert(std::make_pair(78, common::Encode::HexDecode("fa606cd8142cda588e8a87ed1f5ac28a82486025")));
    pool_index_map_.insert(std::make_pair(79, common::Encode::HexDecode("e7c9f08822e6656ba3cdf91cc82aa2c13c4124e5")));
    pool_index_map_.insert(std::make_pair(80, common::Encode::HexDecode("bbe017feddf1e5f1222095ba1e01b395ab8c696c")));
    pool_index_map_.insert(std::make_pair(81, common::Encode::HexDecode("d99549adeb69b4c5a7b49d91641febb06a6ab1ff")));
    pool_index_map_.insert(std::make_pair(82, common::Encode::HexDecode("6b0028207b3ea5ab93b711bac0e232f6a5b97b46")));
    pool_index_map_.insert(std::make_pair(83, common::Encode::HexDecode("c330372faeb47fd57976c8b636fcb58e026a1e33")));
    pool_index_map_.insert(std::make_pair(84, common::Encode::HexDecode("49b18d298a0e28a195004c411666622eb20c7352")));
    pool_index_map_.insert(std::make_pair(85, common::Encode::HexDecode("a50a878bf3a4650677304552270d28eda022f1fc")));
    pool_index_map_.insert(std::make_pair(86, common::Encode::HexDecode("b2e5fca84b3eb00567e755038de2b13e2b1a8593")));
    pool_index_map_.insert(std::make_pair(87, common::Encode::HexDecode("ad146a0dc1580844f179a59973aa6047b1a73191")));
    pool_index_map_.insert(std::make_pair(88, common::Encode::HexDecode("c04affa2c1b71a81a55a7aa547ffb37f41ad60f4")));
    pool_index_map_.insert(std::make_pair(89, common::Encode::HexDecode("a9c8b1675ec84761ca1db326fb1d5c28873f79e7")));
    pool_index_map_.insert(std::make_pair(90, common::Encode::HexDecode("98445070a1a9d8cfd0d0be1c6a74819a7e93ee05")));
    pool_index_map_.insert(std::make_pair(91, common::Encode::HexDecode("a700e5b15ff74230bc87417d612f9a66220abb6f")));
    pool_index_map_.insert(std::make_pair(92, common::Encode::HexDecode("df1b84704fcd6f563b27dabee116b429d7f01b8b")));
    pool_index_map_.insert(std::make_pair(93, common::Encode::HexDecode("802890c9fb2ed5ce7107e9200587da4053415c83")));
    pool_index_map_.insert(std::make_pair(94, common::Encode::HexDecode("1fe9fe89e64d473457fc786f0055c9cc983c1007")));
    pool_index_map_.insert(std::make_pair(95, common::Encode::HexDecode("564ae22d39145e3b96ce4bf0cfb8ec3d1373ea6a")));
    pool_index_map_.insert(std::make_pair(96, common::Encode::HexDecode("dace9a4eba38e6a01d5908d61183a099a3250a6e")));
    pool_index_map_.insert(std::make_pair(97, common::Encode::HexDecode("a53af3069f08c6d738132125135e66079728e29b")));
    pool_index_map_.insert(std::make_pair(98, common::Encode::HexDecode("79e2c29d4ae8776f4a5cbe094191074a8f6ca203")));
    pool_index_map_.insert(std::make_pair(99, common::Encode::HexDecode("7e349163a2f287092fb44f008beb0c3d8a99cab0")));
    pool_index_map_.insert(std::make_pair(100, common::Encode::HexDecode("d0e1678ed3f72d746b30f9da93108bdd0dfb118c")));
    pool_index_map_.insert(std::make_pair(101, common::Encode::HexDecode("c95d283360fe55f2f805764fa4b38e007e09cbd2")));
    pool_index_map_.insert(std::make_pair(102, common::Encode::HexDecode("eacbf7e19e7228e84e73163d82daf483ee5d4914")));
    pool_index_map_.insert(std::make_pair(103, common::Encode::HexDecode("1ea6c24d2cac070da2e7fb9a67e60e8f4098d153")));
    pool_index_map_.insert(std::make_pair(104, common::Encode::HexDecode("7f4f1a29f4a76d5fd19ac1e28559c099b710f7cd")));
    pool_index_map_.insert(std::make_pair(105, common::Encode::HexDecode("dcdf2e2bfafda20f9bcd4ff1ebe5df79f157ae6c")));
    pool_index_map_.insert(std::make_pair(106, common::Encode::HexDecode("d9bf96187b35c255be44d7a9f373a9488d86ee82")));
    pool_index_map_.insert(std::make_pair(107, common::Encode::HexDecode("8f604d2f2528cc54528b56408564d18c9e7cfa70")));
    pool_index_map_.insert(std::make_pair(108, common::Encode::HexDecode("881362e36f055ba9a6acf96b0a151005b77848a9")));
    pool_index_map_.insert(std::make_pair(109, common::Encode::HexDecode("201e726e9fcbab2e73b7e7bcf4e9fad54e384d4a")));
    pool_index_map_.insert(std::make_pair(110, common::Encode::HexDecode("683c1a9c05fe38c78398ef4c2ffc81cdc501ee6a")));
    pool_index_map_.insert(std::make_pair(111, common::Encode::HexDecode("ef1c4fb6425daad06d0b03a8934a5e027ce7cde9")));
    pool_index_map_.insert(std::make_pair(112, common::Encode::HexDecode("d8579e7e374f59126c0d80d06283f5056629aca7")));
    pool_index_map_.insert(std::make_pair(113, common::Encode::HexDecode("9cbad3f61663309726ef5019500a0ee7d5218ada")));
    pool_index_map_.insert(std::make_pair(114, common::Encode::HexDecode("01657d889122fac7ffeae640aa5bab5b79c07f3e")));
    pool_index_map_.insert(std::make_pair(115, common::Encode::HexDecode("db9cc7e32b2c3bae1f2b04a8d714b7cebff005f8")));
    pool_index_map_.insert(std::make_pair(116, common::Encode::HexDecode("ee789aecc43f61534ef667e0d7cb0c0c80ee5713")));
    pool_index_map_.insert(std::make_pair(117, common::Encode::HexDecode("141d9b207b1107505de44fc9bfec4978f19c1bf1")));
    pool_index_map_.insert(std::make_pair(118, common::Encode::HexDecode("87cef9bbfaa38f0bf322b2d987d7ca52acbd9fdd")));
    pool_index_map_.insert(std::make_pair(119, common::Encode::HexDecode("9f8f57d84060ea16a043e57ee64fcd3a65aa24cd")));
    pool_index_map_.insert(std::make_pair(120, common::Encode::HexDecode("7f4ff7d501e2f112a816a161829800001de7d898")));
    pool_index_map_.insert(std::make_pair(121, common::Encode::HexDecode("3cfe684737d50b2e8c3e3f749f845a424c150d85")));
    pool_index_map_.insert(std::make_pair(122, common::Encode::HexDecode("2691b7010c6ab52566eb1ed3558e9e4901496481")));
    pool_index_map_.insert(std::make_pair(123, common::Encode::HexDecode("0cc6f7d5824453e9b9d7c506ca5a2e83c48f0643")));
    pool_index_map_.insert(std::make_pair(124, common::Encode::HexDecode("33ca390701415458c303a679bab4a1f9cd81bf68")));
    pool_index_map_.insert(std::make_pair(125, common::Encode::HexDecode("ba833038f247d6869450d3133e436c6b900cbf30")));
    pool_index_map_.insert(std::make_pair(126, common::Encode::HexDecode("829d5c3fdf7ae4c694be781c465bb2f763b88a5f")));
    pool_index_map_.insert(std::make_pair(127, common::Encode::HexDecode("1c5231064d99bd9ecc7b1a869f943fedd97ce39d")));
    pool_index_map_.insert(std::make_pair(128, common::Encode::HexDecode("c354c7e21f73b97747f3dbad15fe9f5140cf80b6")));
    pool_index_map_.insert(std::make_pair(129, common::Encode::HexDecode("db0794a5a1c12aa2bfc02b254aa26e1f9ec6e602")));
    pool_index_map_.insert(std::make_pair(130, common::Encode::HexDecode("e1ca3f3f1122426bdc1d343da46efff40e13dff4")));
    pool_index_map_.insert(std::make_pair(131, common::Encode::HexDecode("96dc8d547820fb6f643f28def69688c59a4c1eb4")));
    pool_index_map_.insert(std::make_pair(132, common::Encode::HexDecode("773d333c60855dd3112e36c2ab52db63004d8658")));
    pool_index_map_.insert(std::make_pair(133, common::Encode::HexDecode("5ac2b40f80069044a31804b01d854e45e770b29e")));
    pool_index_map_.insert(std::make_pair(134, common::Encode::HexDecode("a33aae517f449db3b6a664c959b54329b9aeabab")));
    pool_index_map_.insert(std::make_pair(135, common::Encode::HexDecode("ab48f4b97a7d8804a49b9e2ee2be8d239ecc81b6")));
    pool_index_map_.insert(std::make_pair(136, common::Encode::HexDecode("0b7834e497f485f3d97fbbc66eb9624e8acd72af")));
    pool_index_map_.insert(std::make_pair(137, common::Encode::HexDecode("a381844b21b1339a355cf2be627f2e106965136a")));
    pool_index_map_.insert(std::make_pair(138, common::Encode::HexDecode("a7ffacc116875a1d06d25d3f2837b2c54279d06b")));
    pool_index_map_.insert(std::make_pair(139, common::Encode::HexDecode("05c8743802ad0e34760221821ca19359cf987841")));
    pool_index_map_.insert(std::make_pair(140, common::Encode::HexDecode("1be3009d38fc1b07fb43b622702f7f273ae7c6bc")));
    pool_index_map_.insert(std::make_pair(141, common::Encode::HexDecode("197bea39ba9a1dd7f472e9c8f8daaae6a9ad444a")));
    pool_index_map_.insert(std::make_pair(142, common::Encode::HexDecode("b2c782862d56181cccff4f8c178ffd9df872bfe4")));
    pool_index_map_.insert(std::make_pair(143, common::Encode::HexDecode("7a7096385a2276c5aced1d02da46477a4a821604")));
    pool_index_map_.insert(std::make_pair(144, common::Encode::HexDecode("96c70e69c659d962d5a35e5f6c4f6804f3e1b686")));
    pool_index_map_.insert(std::make_pair(145, common::Encode::HexDecode("f02a052cc5d9838f3b4503430d77e6ab05e26936")));
    pool_index_map_.insert(std::make_pair(146, common::Encode::HexDecode("4ee2129f46b07294a57ef9dfa05669bb9ef25cf5")));
    pool_index_map_.insert(std::make_pair(147, common::Encode::HexDecode("75145d134a89a7622b9d17b9d827e84e3930c70b")));
    pool_index_map_.insert(std::make_pair(148, common::Encode::HexDecode("1d4caeb4ac1d60ba8bff82a85d04e228065faa91")));
    pool_index_map_.insert(std::make_pair(149, common::Encode::HexDecode("3c9383eb80560531b9acea4911d44560881e10b3")));
    pool_index_map_.insert(std::make_pair(150, common::Encode::HexDecode("75deba2128478ffef3aa90c21ad0cd38ff4d1e33")));
    pool_index_map_.insert(std::make_pair(151, common::Encode::HexDecode("375d381df47e94cce3b8571e716eb28708ac654f")));
    pool_index_map_.insert(std::make_pair(152, common::Encode::HexDecode("b00befc07d08593fb54086a95e4bbb87ef625e3f")));
    pool_index_map_.insert(std::make_pair(153, common::Encode::HexDecode("76f28240fbf8b7f8961cf402023abd688bae8a65")));
    pool_index_map_.insert(std::make_pair(154, common::Encode::HexDecode("0553655d4b4060d7f9be16d2ce72476c0a711ed9")));
    pool_index_map_.insert(std::make_pair(155, common::Encode::HexDecode("65fdb7430c74ad04d4a91784cf082a914eca0dac")));
    pool_index_map_.insert(std::make_pair(156, common::Encode::HexDecode("089690e36c417f11202b73d5ddc67ba49a1cfc26")));
    pool_index_map_.insert(std::make_pair(157, common::Encode::HexDecode("f0b0d6d47afd2a4444b344ba39875316a410d773")));
    pool_index_map_.insert(std::make_pair(158, common::Encode::HexDecode("c78a6f629767bf1b2000f8545762ed9511d348c7")));
    pool_index_map_.insert(std::make_pair(159, common::Encode::HexDecode("7979c0b907b8ac65bcd8adaf04b6518ef824806c")));
    pool_index_map_.insert(std::make_pair(160, common::Encode::HexDecode("8bb54be6347003f1cb3648185d38c55318889d96")));
    pool_index_map_.insert(std::make_pair(161, common::Encode::HexDecode("823d0cf9009bec5d0bb58b629463569a4943c118")));
    pool_index_map_.insert(std::make_pair(162, common::Encode::HexDecode("d6ae49645917e629745f6038f9d20db6160df385")));
    pool_index_map_.insert(std::make_pair(163, common::Encode::HexDecode("31097025acee3a1a345a173dd61033baea1789c0")));
    pool_index_map_.insert(std::make_pair(164, common::Encode::HexDecode("8ab3f6fec0ad221219290c949c01a8b3448ee3b5")));
    pool_index_map_.insert(std::make_pair(165, common::Encode::HexDecode("8f0c05338a5bac56ce8a82184d306de3b40b860f")));
    for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
        std::cout << "pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(security::Secp256k1::Instance()->ToAddressWithPrivateKey(iter->second)) << "\")));" << std::endl;
    }
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
