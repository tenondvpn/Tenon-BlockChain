#include "stdafx.h"
#include "bft/tx_bft.h"

#include "common/global_info.h"
#include "common/random.h"
#include "common/string_utils.h"
#include "contract/contract_manager.h"
#include "contract/contract_utils.h"
#include "block/account_manager.h"
#include "block/proto/block.pb.h"
#include "block/shard_statistic.h"
#include "election/elect_manager.h"
#include "election/elect_utils.h"
#include "network/network_utils.h"
#include "sync/key_value_sync.h"
#include "security/secp256k1.h"
#include "tvm/execution.h"
#include "tvm/tvm_utils.h"
#include "tvm/tenon_host.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/dispatch_pool.h"
#include "bft/gid_manager.h"
#include "timeblock/time_block_manager.h"
#include "timeblock/time_block_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace bft {

TxBft::TxBft() : BftInterface() {}

TxBft::~TxBft() {}

int TxBft::Init() {
    return BftInterface::Init();
}

int TxBft::Prepare(
        bool leader,
        int32_t pool_mod_idx,
        const bft::protobuf::BftMessage& leader_bft_msg,
        std::string* prepare) {
    if (leader) {
        return LeaderCreatePrepare(pool_mod_idx, prepare);
    }

    if (pool_index() >= common::kInvalidPoolIndex) {
        BFT_ERROR("pool index has locked by other leader[%d]!", pool_index());
        return kBftInvalidPackage;
    }

    if (!leader_bft_msg.has_data()) {
        BFT_ERROR("bft::protobuf::BftMessage has no data!");
        return kBftInvalidPackage;
    }

    int32_t invalid_tx_idx = -1;
    int res = kBftSuccess;
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        res = RootBackupCheckPrepare(leader_bft_msg, &invalid_tx_idx, prepare);
    } else {
        res = BackupCheckPrepare(leader_bft_msg, &invalid_tx_idx, prepare);
    }

    if (res != kBftSuccess) {
        BFT_ERROR("backup prepare failed: %d", res);
        *prepare = std::to_string(invalid_tx_idx);
        return res;
    }

    return kBftSuccess;
}

int TxBft::PreCommit(bool leader, std::string& pre_commit) {
    return kBftSuccess;
}

int TxBft::Commit(bool leader, std::string& commit) {
    return kBftSuccess;
}

int TxBft::LeaderCreatePrepare(int32_t pool_mod_idx, std::string* bft_str) {
    uint32_t pool_index = 0;
    std::vector<TxItemPtr> tx_vec;
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        auto leader_count = elect::ElectManager::Instance()->GetNetworkLeaderCount(
            network::kRootCongressNetworkId);
        if (leader_count > 0) {
            int32_t mem_index = elect::ElectManager::Instance()->GetMemberIndex(
                common::GlobalInfo::Instance()->network_id(),
                common::GlobalInfo::Instance()->id());
            if (((int32_t)common::kRootChainPoolIndex % leader_count) == pool_mod_idx) {
                auto tx_ptr = DispatchPool::Instance()->GetRootTx();
                if (tx_ptr != nullptr) {
                    pool_index = common::kRootChainPoolIndex;
                    tx_vec.push_back(tx_ptr);
                }
            }
        }
    }

    if (tx_vec.empty()) {
        DispatchPool::Instance()->GetTx(pool_index, pool_mod_idx, tx_vec);
        if (tx_vec.empty()) {
            return kBftNoNewTxs;
        }
    }

    set_pool_index(pool_index);
    mem_manager_ptr_ = elect::ElectManager::Instance()->GetMemberManager(
        common::GlobalInfo::Instance()->network_id());
    local_member_index_ = mem_manager_ptr_->GetMemberIndex(
        network_id(),
        common::GlobalInfo::Instance()->id());
    LeaderCallTransaction(tx_vec);
    bft::protobuf::TxBft tx_bft;
    auto ltxp = tx_bft.mutable_ltx_prepare();
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        ltxp->add_gid(tx_vec[i]->uni_gid);
        BFT_DEBUG("leader get tx: %s", common::Encode::HexEncode(tx_vec[i]->tx.gid()).c_str());
    }

    *bft_str = tx_bft.SerializeAsString();
    BFT_INFO("leader check leader success elect height: %lu, local_member_index_: %lu, gid: %s",
        elect_height_, local_member_index_, common::Encode::HexEncode(gid_).c_str());
    return kBftSuccess;
}

void TxBft::LeaderCallTransaction(std::vector<TxItemPtr>& tx_vec) {
    bft::protobuf::TxBft res_tx_bft;
    auto ltx_msg = res_tx_bft.mutable_ltx_prepare();
    if (DoTransaction(tx_vec, *ltx_msg) != kBftSuccess) {
        BFT_ERROR("leader do transaction failed!");
        return;
    }

    libff::alt_bn128_G1 bn_sign;
    if (bls::BlsManager::Instance()->Sign(
            min_aggree_member_count(),
            member_count(),
            local_sec_key(),
            prepare_block()->prepare_final_hash(),
            &bn_sign) != bls::kBlsSuccess) {
        BFT_ERROR("leader do transaction sign data failed!");
        return;
    }

    if (LeaderPrecommitOk(
            *ltx_msg,
            leader_index_,
            bn_sign,
            leader_mem_ptr_->id) != bls::kBlsSuccess) {
        BFT_ERROR("leader call LeaderPrecommitOk failed!");
        return;
    }
}

int TxBft::DoTransaction(
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_prepare) {
    if (InitTenonTvmContext() != kBftSuccess) {
        return kBftError;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm_height;
    uint64_t tm_with_block_height;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &pool_height,
        &pool_hash,
        &tm_height,
        &tm_with_block_height);
    if (res != block::kBlockSuccess) {
        assert(false);
        return kBftError;
    }

    protobuf::Block& tenon_block = *(ltx_prepare.mutable_block());
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        RootDoTransactionAndCreateTxBlock(pool_index(), pool_height, tx_vec, tenon_block);
    } else {
        DoTransactionAndCreateTxBlock(tx_vec, tenon_block);
    }

    if (tenon_block.tx_list_size() <= 0) {
        BFT_ERROR("all choose tx invalid!");
        return kBftNoNewTxs;
    }

    tenon_block.set_pool_index(pool_index());
    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(vss::VssManager::Instance()->EpochRandom());
    tenon_block.set_height(pool_height + 1);
    tenon_block.set_timestamp(common::TimeUtils::TimestampMs());
    tenon_block.set_timeblock_height(tmblock::TimeBlockManager::Instance()->LatestTimestampHeight());
    tenon_block.set_electblock_height(elect::ElectManager::Instance()->latest_height(
        common::GlobalInfo::Instance()->network_id()));
    tenon_block.set_leader_index(leader_index_);
    tenon_block.set_hash(GetBlockHash(tenon_block));
    auto block_ptr = std::make_shared<bft::protobuf::Block>(tenon_block);
    SetBlock(block_ptr);
    tbft_prepare_block_ = CreatePrepareTxInfo(block_ptr, ltx_prepare);
    if (tbft_prepare_block_ == nullptr) {
        return kBftError;
    }

    return kBftSuccess;
}

std::shared_ptr<bft::protobuf::TbftLeaderPrepare> TxBft::CreatePrepareTxInfo(
        std::shared_ptr<bft::protobuf::Block>& block_ptr,
        bft::protobuf::LeaderTxPrepare& ltx_prepare) {
    std::string tbft_prepare_txs_str_for_hash;
    auto prepare = ltx_prepare.mutable_prepare();
    for (int32_t i = 0; i < block_ptr->tx_list_size(); ++i) {
        auto tx_hash = GetPrepareTxsHash(block_ptr->tx_list(i));
        if (tx_hash.empty()) {
            continue;
        }

        auto prepare_txs_item = prepare->add_prepare_txs();
        std::string uni_gid = GidManager::Instance()->GetUniversalGid(
            block_ptr->tx_list(i).to_add(),
            block_ptr->tx_list(i).type(),
            block_ptr->tx_list(i).call_contract_step(),
            block_ptr->tx_list(i).gid());
        prepare_txs_item->set_gid(uni_gid);
        prepare_txs_item->set_balance(block_ptr->tx_list(i).balance());
            std::to_string(block_ptr->tx_list(i).balance());
        if (block_ptr->tx_list(i).to_add()) {
            prepare_txs_item->set_address(block_ptr->tx_list(i).to());
        } else {
            prepare_txs_item->set_address(block_ptr->tx_list(i).from());
        }
    }

    if (prepare->prepare_txs_size() <= 0) {
        return nullptr;
    }

    prepare->set_prepare_final_hash(GetBlockHash(*block_ptr));
    prepare->set_height(block_ptr->height());
    set_prepare_hash(prepare->prepare_final_hash());
    return std::make_shared<bft::protobuf::TbftLeaderPrepare>(*prepare);
}

int TxBft::RootBackupCheckPrepare(
        const bft::protobuf::BftMessage& bft_msg,
        int32_t* invalid_tx_idx,
        std::string* prepare) {
    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("bft::protobuf::TxBft ParseFromString failed!");
        return kBftInvalidPackage;
    }

    std::vector<TxItemPtr> tx_vec;
    for (int32_t i = 0; i < tx_bft.ltx_prepare().gid_size(); ++i) {
        TxItemPtr local_tx_info = DispatchPool::Instance()->GetTx(
            pool_index(),
            tx_bft.ltx_prepare().gid(i));
        if (local_tx_info == nullptr) {
            continue;
        }

        tx_vec.push_back(local_tx_info);
        BFT_ERROR("get tx, pool index: %d, gid: %s, type: %d",
            pool_index(),
            common::Encode::HexEncode(tx_bft.ltx_prepare().gid(i)).c_str(),
            local_tx_info->tx.type());
    }

    if (tx_vec.empty()) {
        BFT_ERROR("no tx, pool index: %d, gid: %s",
            pool_index(),
            common::Encode::HexEncode(tx_bft.ltx_prepare().gid(0)).c_str());
        return kBftInvalidPackage;
    }

    bft::protobuf::TxBft res_tx_bft;
    auto ltx_msg = res_tx_bft.mutable_ltx_prepare();
    if (DoTransaction(tx_vec, *ltx_msg) != kBftSuccess) {
        return kBftInvalidPackage;
    }

    ltx_msg->clear_block();
    *prepare = res_tx_bft.SerializeAsString();
    return kBftSuccess;
}

int TxBft::BackupCheckPrepare(
        const bft::protobuf::BftMessage& bft_msg,
        int32_t* invalid_tx_idx,
        std::string* prepare) {
    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("bft::protobuf::TxBft ParseFromString failed!");
        return kBftInvalidPackage;
    }

    std::vector<TxItemPtr> tx_vec;
    for (int32_t i = 0; i < tx_bft.ltx_prepare().gid_size(); ++i) {
        TxItemPtr local_tx_info = DispatchPool::Instance()->GetTx(
            pool_index(),
            tx_bft.ltx_prepare().gid(i));
        if (local_tx_info == nullptr) {
            continue;
        }

        tx_vec.push_back(local_tx_info);
        BFT_ERROR("get tx, pool index: %d, gid: %s, type: %d",
            pool_index(),
            common::Encode::HexEncode(tx_bft.ltx_prepare().gid(i)).c_str(),
            local_tx_info->tx.type());
    }

    if (tx_vec.empty()) {
        BFT_ERROR("no tx, pool index: %d, gid: %s",
            pool_index(),
            common::Encode::HexEncode(tx_bft.ltx_prepare().gid(0)).c_str());
        return kBftInvalidPackage;
    }


    bft::protobuf::TxBft res_tx_bft;
    auto ltx_msg = res_tx_bft.mutable_ltx_prepare();
    if (DoTransaction(tx_vec, *ltx_msg) != kBftSuccess) {
        return kBftInvalidPackage;
    }

    ltx_msg->clear_block();
    *prepare = res_tx_bft.SerializeAsString();
    return kBftSuccess;
}

int TxBft::CheckBlockInfo(const protobuf::Block& block_info) {
    // check hash
    auto hash256 = GetBlockHash(block_info);
    if (hash256 != block_info.hash()) {
        BFT_ERROR("hash256 != block_info.hash() failed!");
        return kBftBlockHashError;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm_height;
    uint64_t tm_with_block_height;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &pool_height,
        &pool_hash,
        &tm_height,
        &tm_with_block_height);
    if (res != block::kBlockSuccess) {
        BFT_ERROR("GetBlockInfo failed!");
        return kBftBlockHashError;
    }

    if (pool_hash != block_info.prehash()) {
        res = sync::KeyValueSync::Instance()->AddSync(
                block_info.network_id(),
                block_info.prehash(),
                sync::kSyncHighest);
        if (res != sync::kSyncBlockReloaded) {
            BFT_ERROR("000 hash block missing pool[%d] now[%s], prev[%s]",
                pool_index(),
                common::Encode::HexEncode(pool_hash).c_str(),
                common::Encode::HexEncode(block_info.prehash()).c_str());
            return kBftBlockPreHashError;
        }

        res = block::AccountManager::Instance()->GetBlockInfo(
            pool_index(),
            &pool_height,
            &pool_hash,
            &tm_height,
            &tm_with_block_height);
        if (res != block::kBlockSuccess) {
            BFT_ERROR("GetBlockInfo failed!");
            return kBftBlockHashError;
        }

        if (pool_hash != block_info.prehash()) {
            BFT_ERROR("111 hash block missing pool[%d] now[%s], prev[%s]",
                    pool_index(),
                    common::Encode::HexEncode(pool_hash).c_str(),
                    common::Encode::HexEncode(block_info.prehash()).c_str());
            return kBftBlockPreHashError;
        }
    }

    if (pool_height + 1 != block_info.height()) {
        BFT_ERROR("block height: %llu, leader height: %llu",
            (pool_height + 1), block_info.height());
        return kBftBlockHeightError;
    }

    if (block_info.timeblock_height() !=
            tmblock::TimeBlockManager::Instance()->LatestTimestampHeight()) {
        BFT_ERROR("time block height: %llu, leader height: %llu",
            block_info.timeblock_height(),
            tmblock::TimeBlockManager::Instance()->LatestTimestampHeight());
        return kBftTimeBlockHeightError;
    }

    if (block_info.electblock_height() !=
            elect::ElectManager::Instance()->latest_height(block_info.network_id())) {
        return kBftElectBlockHeightError;
    }

    return kBftSuccess;
}

int TxBft::CheckTxInfo(
        const protobuf::Block& block_info,
        const protobuf::TxInfo& tx_info,
        TxItemPtr local_tx_info) {
    if (local_tx_info == nullptr) {
        BFT_ERROR("prepare [to: %d] [pool idx: %d] type: %d,"
            "not has tx[%s]to[%s][%s]!",
            tx_info.to_add(),
            pool_index(),
            tx_info.type(),
            common::Encode::HexEncode(tx_info.from()).c_str(),
            common::Encode::HexEncode(tx_info.to()).c_str(),
            common::Encode::HexEncode(tx_info.gid()).c_str());
        return kBftLeaderTxInfoInvalid;
    }

    if (local_tx_info->tx.amount() != tx_info.amount()) {
        BFT_ERROR("local tx balance[%llu] not equal to leader[%llu]!",
                local_tx_info->tx.amount(), tx_info.amount());
        return kBftLeaderTxInfoInvalid;
    }

    if (local_tx_info->tx.from() != tx_info.from()) {
        BFT_ERROR("local tx  from not equal to leader from account![%s][%s]",
            common::Encode::HexEncode(local_tx_info->tx.from()).c_str(),
            common::Encode::HexEncode(tx_info.from()).c_str());
        return kBftLeaderTxInfoInvalid;
    }

    if (local_tx_info->tx.to() != tx_info.to()) {
        BFT_ERROR("local tx  to not equal to leader to account![%s][%s]",
            common::Encode::HexEncode(local_tx_info->tx.to()).c_str(),
            common::Encode::HexEncode(tx_info.to()).c_str());
        return kBftLeaderTxInfoInvalid;
    }

    // just from account can set attrs
    if (!tx_info.to_add()) {
        if (local_tx_info->attr_map.size() != static_cast<uint32_t>(tx_info.attr_size())) {
            BFT_ERROR("local tx attrs not equal to leader attrs[%d][%d]!",
                local_tx_info->attr_map.size(), tx_info.attr_size());
            return kBftLeaderTxInfoInvalid;
        }

        for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
            auto iter = local_tx_info->attr_map.find(tx_info.attr(i).key());
            if (iter == local_tx_info->attr_map.end()) {
                BFT_ERROR("local tx bft key[%s] not equal to leader key!",
                    tx_info.attr(i).key().c_str());
                return kBftLeaderTxInfoInvalid;
            }

            if (iter->second != tx_info.attr(i).value()) {
                BFT_ERROR("key[%s], local tx bft value[%s] not equal to leader value[%s]!",
                    tx_info.attr(i).key().c_str(),
                    iter->second.c_str(), tx_info.attr(i).value().c_str());
                return kBftLeaderTxInfoInvalid;
            }
        }

        if (tx_info.type() == common::kConsensusCreateContract) {
            if (local_tx_info->attr_map.find(kContractBytesCode) == local_tx_info->attr_map.end()) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    BFT_ERROR("local tx bft status[%d] not equal to leader status[%d]!",
                        kBftCreateContractKeyError, tx_info.status());
                    return kBftLeaderTxInfoInvalid;
                }
            }

            auto contract_addr = security::Secp256k1::Instance()->GetContractAddress(
                local_tx_info->tx.from(),
                local_tx_info->tx.gid(),
                local_tx_info->attr_map[kContractBytesCode]);
            if (contract_addr != local_tx_info->tx.to()) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    BFT_ERROR("local tx bft status[%d] not equal to leader status[%d]! from: %s, gid: %s, bytes_code: %s, cpaddr: %s, to: %s",
                        kBftCreateContractKeyError, tx_info.status(),
                        common::Encode::HexEncode(local_tx_info->tx.from()).c_str(),
                        common::Encode::HexEncode(local_tx_info->tx.gid()).c_str(),
                        common::Encode::HexEncode(local_tx_info->attr_map[kContractBytesCode]).c_str(),
                        common::Encode::HexEncode(contract_addr).c_str(),
                        common::Encode::HexEncode(local_tx_info->tx.to()).c_str());
                    return kBftLeaderTxInfoInvalid;
                }
            }
        }
    }

    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (tx_info.type() != common::kConsensusCreateAcount) {
            BFT_ERROR("local tx bft type not equal to leader tx bft type!");
            return kBftLeaderTxInfoInvalid;
        }
    } else {
        if (local_tx_info->tx.type() != tx_info.type()) {
            BFT_ERROR("local tx bft type not equal to leader tx bft type!");
            return kBftLeaderTxInfoInvalid;
        }
    }

    if (tx_info.has_to() && !tx_info.to().empty()) {
    } else {
        // check amount is 0
        // new account address
//         if (common::GetPoolIndex(tx_info.from()) != pool_index()) {
//             return kBftPoolIndexError;
//         }
    }

    add_item_index_vec(local_tx_info->index);
    return kBftSuccess;
}

void TxBft::RootCreateAccountAddressBlock(
        uint32_t pool_idx,
        int64_t pool_height,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block) {
    auto tx_list = tenon_block.mutable_tx_list();
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx = tx_vec[i]->tx;
        tx.set_version(common::kTransactionVersion);
        tx.set_status(kBftSuccess);
        // create address must to and have transfer amount
        if (!tx.to_add() ||
                (tx.amount() <= 0 && tx.type() != common::kConsensusCreateContract)) {
            continue;
        }

        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx.to());
        if (acc_info != nullptr) {
            continue;
        }

        if (tx.type() == common::kConsensusCreateContract) {
            uint32_t network_id = 0;
            if (block::AccountManager::Instance()->GetAddressConsensusNetworkId(
                    tx.from(),
                    &network_id) != block::kBlockSuccess) {
                BFT_ERROR("get network_id error!");
                continue;
            }

            // same to from address's network id
            tx.set_network_id(network_id);
        } else {
            tx.set_network_id(NewAccountGetNetworkId(tx.to()));
        }

        uint32_t local_pool_idx = common::kInvalidPoolIndex;
        if (tx.to() == common::kRootChainSingleBlockTxAddress ||
                tx.to() == common::kRootChainTimeBlockTxAddress ||
                tx.to() == common::kRootChainElectionBlockTxAddress) {
            local_pool_idx = common::kRootChainPoolIndex;
        } else {
            std::mt19937_64 g2(pool_height);
            local_pool_idx = g2() % common::kImmutablePoolSize;
            BFT_DEBUG("set random pool index, pool_height: %lu, local_pool_idx: %d", pool_height, local_pool_idx);
        }

        tx.set_pool_index(local_pool_idx);
        add_item_index_vec(tx_vec[i]->index);
        auto add_tx = tx_list->Add();
        *add_tx = tx;
    }
}

void TxBft::RootCreateElectConsensusShardBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block) {
    if (tx_vec.size() != 1) {
        return;
    }

    protobuf::TxInfo tx = tx_vec[0]->tx;
    if (tx.type() != common::kConsensusRootElectShard) {
        assert(false);
        return;
    }

    // use new node status
    if (elect::ElectManager::Instance()->GetElectionTxInfo(tx) != elect::kElectSuccess) {
        assert(false);
        return;
    }

    // (TODO): check elect is valid in the time block period,
    // one time block, one elect block
    // check after this shard statistic block coming
    auto tx_list = tenon_block.mutable_tx_list();
    auto add_tx = tx_list->Add();
    *add_tx = tx;
}

void TxBft::RootDoTransactionAndCreateTxBlock(
        uint32_t pool_idx,
        uint64_t pool_height,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block) {
    if (tx_vec.size() == 1) {
        switch (tx_vec[0]->tx.type())
        {
        case common::kConsensusRootElectShard:
            RootCreateElectConsensusShardBlock(pool_idx, tx_vec, tenon_block);
            break;
        case common::kConsensusRootTimeBlock:
            RootCreateTimerBlock(pool_idx, tx_vec, tenon_block);
            break;
        case common::kConsensusFinalStatistic:
            RootCreateFinalStatistic(pool_idx, tx_vec, tenon_block);
            break;
        default:
            RootCreateAccountAddressBlock(pool_idx, pool_height, tx_vec, tenon_block);
            break;
        }
    } else {
        RootCreateAccountAddressBlock(pool_idx, pool_height, tx_vec, tenon_block);
    }
}

void TxBft::RootCreateFinalStatistic(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block) {
    protobuf::TxInfo tx = tx_vec[0]->tx;
    tx.set_version(common::kTransactionVersion);
    tx.set_amount(0);
    tx.set_gas_limit(0);
    tx.set_network_id(common::GlobalInfo::Instance()->network_id());
    tx.set_gas_used(0);
    tx.set_balance(0);
    tx.set_status(kBftSuccess);
    for (int32_t i = 0; i < tx.attr_size(); ++i) {
        if (tx.attr(i).key() == tmblock::kAttrTimerBlockHeight) {
            block::protobuf::StatisticInfo statistic_info;
            uint64_t timeblock_height = 0;
            if (common::StringUtil::ToUint64(tx.attr(i).value(), &timeblock_height)) {
                block::ShardStatistic::Instance()->GetStatisticInfo(
                    timeblock_height,
                    &statistic_info);
                auto statistic_attr = tx.add_storages();
                statistic_attr->set_key(bft::kStatisticAttr);
                statistic_attr->set_value(statistic_info.SerializeAsString());
            }
        }
    }

    // (TODO): check elect is valid in the time block period,
    // one time block, one elect block
    // check after this shard statistic block coming
    auto tx_list = tenon_block.mutable_tx_list();
    auto add_tx = tx_list->Add();
    *add_tx = tx;
    if (tx_list->empty()) {
        BFT_ERROR("leader has no tx to consensus.");
        return;
    }

    add_item_index_vec(tx_vec[0]->index);
}

void TxBft::RootCreateTimerBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block) {
    protobuf::TxInfo tx = tx_vec[0]->tx;
    tx.set_version(common::kTransactionVersion);
    tx.set_amount(0);
    tx.set_gas_limit(0);
    tx.set_gas_used(0);
    tx.set_balance(0);
    tx.set_status(kBftSuccess);
    // create address must to and have transfer amount
    if (tx.type() != common::kConsensusRootTimeBlock) {
        BFT_ERROR("tx is not timeblock tx");
        return;
    }

    // (TODO): check elect is valid in the time block period,
    // one time block, one elect block
    // check after this shard statistic block coming
    auto tx_list = tenon_block.mutable_tx_list();
    auto add_tx = tx_list->Add();
    *add_tx = tx;
    add_item_index_vec(tx_vec[0]->index);
}

int TxBft::GetTempAccountBalance(
        const std::string& id,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        uint64_t* balance) {
    auto iter = acc_balance_map.find(id);
    if (iter == acc_balance_map.end()) {
        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(id);
        if (acc_info == nullptr) {
            BFT_ERROR("account addres not exists[%s]", common::Encode::HexEncode(id).c_str());
            return kBftAccountNotExists;
        }

        uint64_t db_balance = 0;
        if (acc_info->GetBalance(&db_balance) != block::kBlockSuccess) {
            BFT_ERROR("account addres exists but balance not exists[%s]",
                common::Encode::HexEncode(id).c_str());
            return kBftAccountNotExists;
        }

        acc_balance_map[id] = db_balance;
        *balance = db_balance;
    } else {
        *balance = iter->second;
    }

    return kBftSuccess;
}

void TxBft::DoTransactionAndCreateTxBlock(
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block) {
    auto tx_list = tenon_block.mutable_tx_list();
    std::unordered_map<std::string, int64_t> acc_balance_map;
    std::unordered_map<std::string, bool> locked_account_map;
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx = tx_vec[i]->tx;
        tx.set_version(common::kTransactionVersion);
        tx.set_gas_price(common::GlobalInfo::Instance()->gas_price());
        tx.set_status(kBftSuccess);
        if (tx.type() == common::kConsensusCallContract ||
                tx.type() == common::kConsensusCreateContract) {
            if (AddCallContract(
                    tx_vec[i],
                    acc_balance_map,
                    locked_account_map,
                    tx) != kBftSuccess) {
                BFT_ERROR("leader call contract failed!");
                continue;
            }
        } else if (tx.type() == common::kConsensusFinalStatistic) {
            for (int32_t i = 0; i < tx.attr_size(); ++i) {
                if (tx.attr(i).key() == tmblock::kAttrTimerBlockHeight) {
                    block::protobuf::StatisticInfo statistic_info;
                    uint64_t timeblock_height = 0;
                    if (common::StringUtil::ToUint64(tx.attr(i).value(), &timeblock_height)) {
                        block::ShardStatistic::Instance()->GetStatisticInfo(
                            timeblock_height,
                            &statistic_info);
                        auto statistic_attr = tx.add_storages();
                        statistic_attr->set_key(bft::kStatisticAttr);
                        statistic_attr->set_value(statistic_info.SerializeAsString());
                    }
                }
            }

            tx.set_network_id(common::GlobalInfo::Instance()->network_id());
            tx.set_gas_used(0);
            tx.set_balance(0);
        } else {
            if (AddNormalTransaction(
                    tx_vec[i],
                    acc_balance_map,
                    locked_account_map,
                    tx) != kBftSuccess) {
                continue;
            }
        }

        add_item_index_vec(tx_vec[i]->index);
        auto add_tx = tx_list->Add();
        *add_tx = tx;
    }
}

int TxBft::AddNormalTransaction(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    if (!tx_info->tx.to_add()) {
        if (locked_account_map.find(tx.from()) != locked_account_map.end()) {
            BFT_ERROR("contract has locked[%s]", common::Encode::HexEncode(tx_info->tx.to()).c_str());
            return kBftContractAddressLocked;
        }

        auto account_info = block::AccountManager::Instance()->GetAcountInfo(tx.from());
        if (account_info->locked()) {
            locked_account_map[tx.from()] = true;
            return kBftError;
        }

        int balance_status = GetTempAccountBalance(tx.from(), acc_balance_map, &from_balance);
        if (balance_status != kBftSuccess) {
            tx.set_status(balance_status);
            // will never happen
            assert(false);
            return kBftError;
        }

        do 
        {
            gas_used = kTransferGas;
            if (!tx_info->attr_map.empty()) {
                for (auto iter = tx_info->attr_map.begin();
                    iter != tx_info->attr_map.end(); ++iter) {
                    gas_used += (iter->first.size() + iter->second.size()) *
                        kKeyValueStorageEachBytes;
                }
            }

            if (from_balance < tx_info->tx.gas_limit()  * tx.gas_price()) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }

            if (tx.gas_limit() < gas_used) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }
        } while (0);
    } else {
        int balance_status = GetTempAccountBalance(tx.to(), acc_balance_map, &to_balance);
        if (balance_status != kBftSuccess) {
            tx.set_status(balance_status);
            assert(false);
            return kBftError;
        }
    }

    if (!tx_info->tx.to_add()) {
        if (tx.status() == kBftSuccess) {
            uint64_t dec_amount = tx_info->tx.amount() + gas_used * tx.gas_price();
            if (from_balance >= gas_used * tx.gas_price()) {
                if (from_balance >= dec_amount) {
                    from_balance -= dec_amount;
                } else {
                    from_balance -= gas_used * tx.gas_price();
                    tx.set_status(kBftAccountBalanceError);
                    BFT_ERROR("leader balance error: %llu, %llu", from_balance, dec_amount);
                }
            } else {
                from_balance = 0;
                tx.set_status(kBftAccountBalanceError);
                BFT_ERROR("leader balance error: %llu, %llu", from_balance, gas_used * tx.gas_price());
            }
        } else {
            if (from_balance >= gas_used * tx.gas_price()) {
                    from_balance -= gas_used * tx.gas_price();
            } else {
                from_balance = 0;
            }
        }

        acc_balance_map[tx_info->tx.from()] = from_balance;
        tx.set_balance(from_balance);
        tx.set_gas_used(gas_used);
    } else {
        if (tx.status() == kBftSuccess) {
            to_balance += tx_info->tx.amount();
        }

        acc_balance_map[tx_info->tx.to()] = to_balance;
        tx.set_balance(to_balance);
        tx.set_gas_used(0);
    }

    return kBftSuccess;
}

int TxBft::AddCallContract(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& out_tx) {
    switch (tx_info->tx.call_contract_step()) {
    case contract::kCallStepDefault:
        return CallContractDefault(tx_info, acc_balance_map, locked_account_map, out_tx);
    case contract::kCallStepCallerInited:
        return CallContractExceute(tx_info, acc_balance_map, out_tx);
    case contract::kCallStepContractCalled:
        return CallContractCalled(tx_info, acc_balance_map, out_tx);
    default:
        break;
    }

    return kBftError;
}

int TxBft::CallContractDefault(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx) {
    if (locked_account_map.find(tx.from()) != locked_account_map.end()) {
        BFT_ERROR("contract has locked[%s]", common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftContractAddressLocked;
    }

    auto account_info = block::AccountManager::Instance()->GetAcountInfo(tx.from());
    if (account_info->locked()) {
        locked_account_map[tx.from()] = true;
        return kBftError;
    }

    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(tx.from(), acc_balance_map, &from_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    uint64_t gas_used = kCallContractDefaultUseGas;
    for (auto iter = tx_info->attr_map.begin();
            iter != tx_info->attr_map.end(); ++iter) {
        gas_used += (iter->first.size() + iter->second.size()) *
            kKeyValueStorageEachBytes;
    }

    // at least kCallContractDefaultUseGas + kTransferGas to call contract.
    if (from_balance < tx.gas_limit() * tx.gas_price() ||
            from_balance <= (gas_used + kTransferGas) * tx.gas_price() ||
            tx.gas_limit() < (gas_used + kTransferGas)) {
        BFT_ERROR("from balance error from_balance: %lu,"
            "tx.gas_limit() * tx.gas_price(): %lu,"
            "(gas_used + kTransferGas) * tx.gas_price(): %lu,"
            "tx.gas_limit(): %lu, (gas_used + kTransferGas): %lu",
            from_balance,
            ((gas_used + kTransferGas) * tx.gas_price()),
            ((gas_used + kTransferGas) * tx.gas_price()),
            tx.gas_limit(),
            (gas_used + kTransferGas));
        tx.set_status(kBftAccountBalanceError);
    }

    if (from_balance >= gas_used * tx.gas_price()) {
        from_balance -= gas_used * tx.gas_price();
    } else {
        from_balance = 0;
        tx.set_status(kBftAccountBalanceError);
    }
    
    acc_balance_map[tx_info->tx.from()] = from_balance;
    tx.set_balance(from_balance);
    tx.set_gas_used(gas_used);
    tx.set_call_contract_step(contract::kCallStepCallerInited);
    if (tx.status() == kBftSuccess) {
        tx.set_gas_limit(tx_info->tx.gas_limit() - gas_used);
        locked_account_map[tx.from()] = true;
    }

    return kBftSuccess;
}

int TxBft::CallContractExceute(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t caller_balance = tx_info->tx.balance();
    uint64_t contract_balance = 0;
    int balance_status = GetTempAccountBalance(
        tx_info->tx.to(),
        acc_balance_map,
        &contract_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        return kBftError;
    }

    evmc_result evmc_res = {};
    evmc::result res{ evmc_res };
    tenon_host_.my_address_ = tx_info->tx.to();
    do
    {
        if (caller_balance < tx_info->tx.gas_limit() * tx.gas_price()) {
            BFT_ERROR("caller_balance: %lu <= tx_info->tx.gas_limit() * tx.gas_price(): %lu ",
                caller_balance, tx_info->tx.gas_limit() * tx.gas_price());
            tx.set_status(kBftUserSetGasLimitError);
            break;
        }

        if (tx_info->tx.type() == common::kConsensusCallContract) {
            // will return from address's remove tenon and gas used
            tenon_host_.AddTmpAccountBalance(
                tx_info->tx.from(),
                caller_balance);
            tenon_host_.AddTmpAccountBalance(
                tx_info->tx.to(),
                contract_balance);
            int call_res = CallContract(tx_info, &tenon_host_, &res);
            gas_used = tx_info->tx.gas_limit() - res.gas_left;
            if (call_res != kBftSuccess) {
                BFT_ERROR("call contract failed![%d]", call_res);
                tx.set_status(kBftExecuteContractFailed);
                break;
            }

            if (res.status_code != EVMC_SUCCESS) {
                BFT_ERROR("call contract failed! res.status_code[%d]", res.status_code);
                tx.set_status(kBftExecuteContractFailed);
                break;
            }
        } else {
            if (tx_info->attr_map.find(kContractBytesCode) == tx_info->attr_map.end()) {
                BFT_ERROR("kContractBytesCode find failed!");
                tx.set_status(kBftCreateContractKeyError);
                break;
            }

            if (security::Secp256k1::Instance()->GetContractAddress(
                    tx_info->tx.from(),
                    tx_info->tx.gid(),
                    tx_info->attr_map[kContractBytesCode]) != tx_info->tx.to()) {
                BFT_ERROR("contract address not eq!");
                tx.set_status(kBftCreateContractKeyError);
                break;
            }

            tenon_host_.AddTmpAccountBalance(
                tx_info->tx.from(),
                caller_balance);
            int call_res = CreateContractCallExcute(
                tx_info,
                tx.gas_limit() - gas_used,
                tx_info->attr_map[kContractBytesCode],
                &tenon_host_,
                &res);
            gas_used += tx.gas_limit() - gas_used - res.gas_left;
            if (call_res != kBftSuccess) {
                BFT_ERROR("CreateContractCallExcute error!");
                tx.set_status(kBftCreateContractKeyError);
                break;
            }

            if (res.status_code != EVMC_SUCCESS) {
                BFT_ERROR("res.status_code != EVMC_SUCCESS!");
                tx.set_status(kBftExecuteContractFailed);
                break;
            }

            if (gas_used > tx_info->tx.gas_limit()) {
                BFT_ERROR("gas_used > tx_info->tx.gas_limit()!");
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }

            auto bytes_code_attr = tx.add_storages();
            bytes_code_attr->set_id(tx_info->tx.to());
            bytes_code_attr->set_key(kContractCreatedBytesCode);
            bytes_code_attr->set_value(tenon_host_.create_bytes_code_);
        }
    } while (0);

    // use execute contract transfer amount to change from balance
    int64_t contract_balance_add = 0;
    int64_t caller_balance_add = 0;
    if (tx.status() == kBftSuccess) {
        for (auto account_iter = tenon_host_.accounts_.begin();
                account_iter != tenon_host_.accounts_.end(); ++account_iter) {
            for (auto storage_iter = account_iter->second.storage.begin();
                    storage_iter != account_iter->second.storage.end(); ++storage_iter) {
                std::string id(
                    (char*)account_iter->first.bytes,
                    sizeof(account_iter->first.bytes));
                std::string key(
                    (char*)storage_iter->first.bytes,
                    sizeof(storage_iter->first.bytes));
                std::string value(
                    (char*)storage_iter->second.value.bytes,
                    sizeof(storage_iter->second.value.bytes));
                auto attr = tx.add_storages();
                attr->set_id(id);
                attr->set_key(key);
                attr->set_value(value);
            }
        }

        for (auto transfer_iter = tenon_host_.to_account_value_.begin();
                transfer_iter != tenon_host_.to_account_value_.end(); ++transfer_iter) {
            // transfer from must caller or contract address, other not allowed.
            assert(transfer_iter->first == tx_info->tx.from() ||
                transfer_iter->first == tx_info->tx.to());
            for (auto to_iter = transfer_iter->second.begin();
                    to_iter != transfer_iter->second.end(); ++to_iter) {
                assert(transfer_iter->first != to_iter->first);
                if (tx_info->tx.to() == transfer_iter->first) {
                    contract_balance_add -= to_iter->second;
                }

                if (tx_info->tx.to() == to_iter->first) {
                    contract_balance_add += to_iter->second;
                }

                if (tx_info->tx.from() == transfer_iter->first) {
                    caller_balance_add -= to_iter->second;
                }

                if (tx_info->tx.from() == to_iter->first) {
                    caller_balance_add += to_iter->second;
                }

                auto trans_item = tx.add_transfers();
                trans_item->set_from(transfer_iter->first);
                trans_item->set_to(to_iter->first);
                trans_item->set_amount(to_iter->second);
            }
        }

        if ((int64_t)caller_balance + caller_balance_add - tx_info->tx.amount() >= gas_used * tx.gas_price()) {
        } else {
            if (tx.status() == kBftSuccess) {
                tx.set_status(kBftAccountBalanceError);
            }
        }

        if (tx.status() == kBftSuccess) {
            if (caller_balance_add < 0) {
                if (caller_balance < (uint64_t)(-caller_balance_add) + tx_info->tx.amount()) {
                    if (tx.status() == kBftSuccess) {
                        tx.set_status(kBftAccountBalanceError);
                    }
                }
            }
        }

        if (tx.status() == kBftSuccess) {
            if (tx_info->tx.amount() > 0) {
                if (caller_balance < tx_info->tx.amount()) {
                    if (tx.status() == kBftSuccess) {
                        tx.set_status(kBftAccountBalanceError);
                    }
                }
            }
        }

        if (tx.status() == kBftSuccess) {
            if (contract_balance_add < 0) {
                if (contract_balance < (uint64_t)(-contract_balance_add)) {
                    if (tx.status() == kBftSuccess) {
                        tx.set_status(kBftAccountBalanceError);
                    }
                } else {
                    contract_balance -= (uint64_t)(-contract_balance_add);
                }
            } else {
                contract_balance += contract_balance_add;
            }
        }
    } else {
        if (caller_balance >= gas_used * tx.gas_price()) {
        } else {
            if (tx.status() == kBftSuccess) {
                tx.set_status(kBftAccountBalanceError);
            }
        }
    }

    contract_balance += tx_info->tx.amount();
    auto caller_balance_attr = tx.add_storages();
    caller_balance_attr->set_key(kContractCallerChangeAmount);
    caller_balance_attr->set_value(std::to_string(caller_balance_add - (int64_t)tx_info->tx.amount()));
    auto gas_limit_attr = tx.add_storages();
    gas_limit_attr->set_key(kContractCallerGasUsed);
    gas_limit_attr->set_value(std::to_string(gas_used));
    acc_balance_map[tx_info->tx.to()] = contract_balance;
    tx.set_balance(contract_balance);
    tx.set_gas_used(0);
    tx.set_call_contract_step(contract::kCallStepContractCalled);
    return kBftSuccess;
}

int TxBft::CreateContractCallExcute(
        TxItemPtr tx_info,
        uint64_t gas_limit,
        const std::string& bytes_code,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res) {
    std::string input;
    uint32_t call_mode = tvm::kJustCreate;
    auto iter = tx_info->attr_map.find(kContractInputCode);
    if (iter != tx_info->attr_map.end()) {
        input = iter->second;
        call_mode = tvm::kCreateAndCall;
    }
//     tvm::Execution exec;
    int exec_res = tvm::Execution::Instance()->execute(
        bytes_code,
        input,
        tx_info->tx.from(),
        tx_info->tx.to(),
        tx_info->tx.from(),
        tx_info->tx.amount(),
        gas_limit,
        0,
        call_mode,
        *tenon_host,
        out_res);
    if (exec_res != tvm::kTvmSuccess) {
        BFT_ERROR("CreateContractCallExcute failed: %d", exec_res);
        return kBftError;
    }

    return kBftSuccess;
}

int TxBft::CallContract(
        TxItemPtr tx_info,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res) {
    std::string input;
    auto iter = tx_info->attr_map.find(kContractInputCode);
    if (iter != tx_info->attr_map.end()) {
        input = iter->second;
    }

    auto contract_info = block::AccountManager::Instance()->GetAcountInfo(tx_info->tx.to());
    if (contract_info == nullptr) {
        BFT_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

    uint32_t address_type = block::kNormalAddress;
    if (contract_info->GetAddressType(&address_type) != block::kBlockSuccess  ||
            address_type != block::kContractAddress) {
        BFT_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

    std::string bytes_code;
    if (contract_info->GetBytesCode(&bytes_code) != block::kBlockSuccess) {
        BFT_ERROR("contract bytes code not exists[%s]",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

//     tvm::Execution exec;
    int exec_res = tvm::Execution::Instance()->execute(
        bytes_code,
        input,
        tx_info->tx.from(),
        tx_info->tx.to(),
        tx_info->tx.from(),
        tx_info->tx.amount(),
        tx_info->tx.gas_limit(),
        0,
        tvm::kJustCall,
        *tenon_host,
        out_res);
    if (exec_res != tvm::kTvmSuccess) {
        return kBftError;
    }

    return kBftSuccess;
}

int TxBft::CallContractCalled(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    // gas just consume by from
    uint64_t from_balance = 0;
    int balance_status = GetTempAccountBalance(tx_info->tx.from(), acc_balance_map, &from_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    auto account_info = block::AccountManager::Instance()->GetAcountInfo(tx_info->tx.from());
    if (!account_info->locked()) {
        BFT_ERROR("account not locked for contrtact: %s",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

    int64_t caller_balance_add = 0;
    uint64_t caller_gas_used = 0;
    for (int32_t i = 0; i < tx_info->tx.storages_size(); ++i) {
        if (tx_info->tx.storages(i).key() == kContractCallerChangeAmount) {
            if (!common::StringUtil::ToInt64(
                    tx_info->tx.storages(i).value(),
                    &caller_balance_add)) {
                return kBftError;
            }

            if (tx_info->tx.status() == kBftSuccess) {
                if (caller_balance_add < 0) {
                    if (from_balance < (uint64_t)(-caller_balance_add)) {
                        return kBftError;
                    }

                    from_balance -= (uint64_t)(-caller_balance_add);
                } else {
                    from_balance += (uint64_t)(caller_balance_add);
                }
            }
        }

        if (tx_info->tx.storages(i).key() == kContractCallerGasUsed) {
            if (!common::StringUtil::ToUint64(tx_info->tx.storages(i).value(), &caller_gas_used)) {
                return kBftError;
            }

            if (from_balance >= caller_gas_used * tx_info->tx.gas_price()) {
                from_balance -= caller_gas_used * tx_info->tx.gas_price();
            } else {
                assert(tx_info->tx.status() != kBftSuccess);
                from_balance = 0;
                if (tx.status() == kBftSuccess) {
                    tx.set_status(kBftAccountBalanceError);
                }
            }
        }
    }

    acc_balance_map[tx_info->tx.from()] = from_balance;
    tx.set_balance(from_balance);
    tx.set_gas_used(caller_gas_used);
    tx.set_call_contract_step(contract::kCallStepContractFinal);
    return kBftSuccess;
}

}  // namespace bft

}  //namespace tenon
