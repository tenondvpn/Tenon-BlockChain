#include "stdafx.h"
#include "bft/bft_manager.h"

#include <cassert>

#include "bft/bft_utils.h"
#include "bft/tx_pool_manager.h"
#include "bft/tx_bft.h"
#include "bft/proto/bft_proto.h"
#include "bft/dispatch_pool.h"
#include "block/block_manager.h"
#include "block/account_manager.h"
#include "bls/bls_utils.h"
#include "bls/bls_manager.h"
#include "bls/bls_sign.h"
#include "common/hash.h"
#include "common/global_info.h"
#include "common/random.h"
#include "common/time_utils.h"
#include "db/db.h"
#include "dht/base_dht.h"
#include "election/elect_manager.h"
#include "election/elect_dht.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "security/schnorr.h"
#include "security/secp256k1.h"
#include "security/crypto.h"
#include "sync/key_value_sync.h"
#include "sync/sync_utils.h"
#include "statistics/statistics.h"
#include "timeblock/time_block_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace bft {

BftManager::BftManager() {
    network::Route::Instance()->RegisterMessage(
        common::kBftMessage,
        std::bind(&BftManager::HandleMessage, this, std::placeholders::_1));
    timeout_tick_.CutOff(
        kBftTimeoutCheckPeriod,
        std::bind(&BftManager::CheckTimeout, this));
    BlockToDb();
//     CheckCommitBackupRecall();
}

BftManager::~BftManager() {}

BftManager* BftManager::Instance() {
    static BftManager ins;
    return &ins;
}

uint32_t BftManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    return elect::ElectManager::Instance()->GetMemberIndex(network_id, node_id);
}

void BftManager::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
//     uint64_t b_time = common::TimeUtils::TimestampUs();
    auto& header = *header_ptr;
    assert(header.type() == common::kBftMessage);
    BftItemPtr bft_item_ptr = std::make_shared<BftItem>();
    bft_item_ptr->header_ptr = header_ptr;
    bft::protobuf::BftMessage& bft_msg = bft_item_ptr->bft_msg;
    if (!bft_msg.ParseFromString(header.data())) {
        BFT_ERROR("protobuf::BftMessage ParseFromString failed!");
        return;
    }

    BFT_DEBUG("msg id: %lu, leader: %d, HandleMessage %s, step: %d, from:%s:%d, bft_msg.bft_step(): %d",
        header.id(),
        bft_msg.leader(),
        common::Encode::HexEncode(bft_msg.gid()).c_str(),
        bft_msg.bft_step(), header.from_ip().c_str(), header.from_port(),
        bft_msg.bft_step());
    assert(bft_msg.has_bft_step());
    if (!bft_msg.has_bft_step()) {
        BFT_ERROR("bft message not has bft step failed!");
        return;
    }

//     uint64_t time1 = common::TimeUtils::TimestampUs();
    // TODO: check account address's network id valid. and this node is valid bft node
    switch (bft_msg.bft_step()) {
    case kBftInit:
        InitBft(header, bft_msg);
        return;
    case kBftToTxInit:
        HandleToAccountTxBlock(header, bft_msg);
        return;
    case kBftRootBlock:
        HandleRootTxBlock(header, bft_msg);
        return;
    case kBftSyncBlock:
        HandleSyncBlock(header, bft_msg);
        return;
    default:
        break;
    }

    // leader 
    if (bft_msg.leader()) {
        auto bft_ptr = GetBft(bft_msg.gid());
        if (bft_ptr == nullptr) {
            BFT_DEBUG("leader get bft gid failed[%s]",
                common::Encode::HexEncode(bft_msg.gid()).c_str());
            return;
        }

        if (!bft_ptr->this_node_is_leader()) {
            return;
        }

//         uint64_t time2 = common::TimeUtils::TimestampUs();
        HandleBftMessage(bft_ptr, bft_msg, header_ptr);
//         uint64_t time3 = common::TimeUtils::TimestampUs();
//         BFT_DEBUG("leader HandleBftMessage time use: %lu, %lu, %lu", time1 - b_time, time2 - time1, time3 - time2);
        return;
    }

    // backup
    BftInterfacePtr bft_ptr = nullptr;
    if (bft_msg.bft_step() == kBftPrepare) {
        bft_ptr = GetBft(bft_msg.gid());
        if (bft_ptr == nullptr) {
            bft_ptr = CreateBftPtr(bft_msg);
            bft_ptr->BackupCheckLeaderValid(bft_msg);
        }

        HandleBftMessage(bft_ptr, bft_msg, header_ptr);
    } else {
        bft_ptr = GetBft(bft_msg.gid());
        if (bft_ptr == nullptr) {
            if (!bft_msg.agree()) {
                BFT_ERROR("BackupPrecommit LeaderCallCommitOppose gid: %s", common::Encode::HexEncode(bft_msg.gid()).c_str());
                return;
            }

            if (bft_msg.bft_step() > kBftCommit) {
                return;
            }

            bft_ptr = CreateBftPtr(bft_msg);
            bft_ptr->BackupCheckLeaderValid(bft_msg);
        }

        bft_ptr->AddMsgStepPtr(bft_msg.bft_step(), bft_item_ptr);
    }

    if (bft_msg.bft_step() == kBftCommit && bft_ptr->status() != kBftCommit) {
        sync::KeyValueSync::Instance()->AddSync(
            bft_msg.net_id(),
            bft_msg.prepare_hash(),
            sync::kSyncHighest);
//         BFT_DEBUG("kBftCommit add bft block pre hash sync: %s, bft gid: %s",
//             common::Encode::HexEncode(bft_msg.prepare_hash()).c_str(),
//             common::Encode::HexEncode(bft_ptr->gid()).c_str());
    }

    if (!bft_ptr->prpare_block()) {
        return;
    }

    assert(!bft_ptr->prepare_hash().empty());
    if (bft_ptr->GetEpoch() < bft_msg.epoch()) {
        HandleBftMessage(bft_ptr, bft_msg, header_ptr);
//         BFT_DEBUG("kBftPreCommit direct msg id: %lu, HandleMessage %s, step: %d, from:%s:%d, bft gid: %s",
//             header.id(),
//             common::Encode::HexEncode(bft_msg.gid()).c_str(),
//             bft_msg.bft_step(), header.from_ip().c_str(), header.from_port(),
//             common::Encode::HexEncode(bft_ptr->gid()).c_str());
        bft_ptr->SetEpoch(bft_msg.epoch());
        return;
    }

    if (bft_ptr->status() == kBftPreCommit) {
        if (bft_msg.bft_step() == kBftPreCommit) {
            HandleBftMessage(bft_ptr, bft_msg, header_ptr);
//             BFT_DEBUG("kBftPreCommit direct msg id: %lu, HandleMessage %s, step: %d, from:%s:%d, bft gid: %s",
//                 header.id(),
//                 common::Encode::HexEncode(bft_msg.gid()).c_str(),
//                 bft_msg.bft_step(), header.from_ip().c_str(), header.from_port(),
//                 common::Encode::HexEncode(bft_ptr->gid()).c_str());
        } else {
            auto bft_item_ptr = bft_ptr->GetMsgStepPtr(kBftPreCommit);
            if (bft_item_ptr == nullptr) {
                return;
            }

//             BFT_DEBUG("kBftPreCommit history recover msg id: %lu, HandleMessage %s, step: %d, from:%s:%d, bft gid: %s",
//                 header.id(),
//                 common::Encode::HexEncode(bft_msg.gid()).c_str(),
//                 bft_msg.bft_step(), header.from_ip().c_str(), header.from_port(),
//                 common::Encode::HexEncode(bft_ptr->gid()).c_str());
            HandleBftMessage(bft_ptr, bft_item_ptr->bft_msg, bft_item_ptr->header_ptr);
        }
    }

    if (bft_ptr->status() == kBftCommit) {
        if (bft_msg.bft_step() == kBftCommit) {
            HandleBftMessage(bft_ptr, bft_msg, header_ptr);
//             BFT_DEBUG("kBftCommit direct msg id: %lu, HandleMessage %s, step: %d, from:%s:%d, bft gid: %s",
//                 header.id(),
//                 common::Encode::HexEncode(bft_msg.gid()).c_str(),
//                 bft_msg.bft_step(), header.from_ip().c_str(), header.from_port(),
//                 common::Encode::HexEncode(bft_ptr->gid()).c_str());
        } else {
            auto bft_item_ptr = bft_ptr->GetMsgStepPtr(kBftCommit);
            if (bft_item_ptr == nullptr) {
                return;
            }

//             BFT_DEBUG("kBftCommit history recover msg id: %lu, HandleMessage %s, step: %d, from:%s:%d, bft gid: %s",
//                 header.id(),
//                 common::Encode::HexEncode(bft_msg.gid()).c_str(),
//                 bft_msg.bft_step(), header.from_ip().c_str(), header.from_port(),
//                 common::Encode::HexEncode(bft_ptr->gid()).c_str());
            HandleBftMessage(bft_ptr, bft_item_ptr->bft_msg, bft_item_ptr->header_ptr);
        }
    }
}

void BftManager::HandleBftMessage(
        BftInterfacePtr& bft_ptr,
        bft::protobuf::BftMessage& bft_msg,
        const transport::TransportMessagePtr& header_ptr) {
    if (!bft_msg.leader()) {
        if (bft_ptr->ThisNodeIsLeader(bft_msg)) {
//             BFT_ERROR("BackupPrecommit LeaderCallCommitOppose gid: %s",
//                 common::Encode::HexEncode(bft_ptr->gid()).c_str());
//             RemoveBft(bft_ptr->gid(), false);
            BFT_DEBUG("this node is leader not handle backup message.");
            return;
        }
    }

    auto& header = *header_ptr;
    switch (bft_msg.bft_step()) {
    case kBftPrepare: {
        if (!bft_msg.leader()) {
            BackupPrepare(bft_ptr, header, bft_msg);
        } else {
            LeaderPrecommit(bft_ptr, header, bft_msg);
        }
        break;
    }
    case kBftPreCommit: {
        if (!bft_msg.leader()) {
            BackupPrecommit(bft_ptr, header, bft_msg);
        } else {
            LeaderCommit(bft_ptr, header, bft_msg);
        }
        break;
    }
    case kBftCommit: {
        if (!bft_msg.leader()) {
            BackupCommit(bft_ptr, header, bft_msg);
        } else {
            assert(false);
        }
        break;
    }
    default:
        assert(false);
        break;
    }
}

BftInterfacePtr BftManager::CreateBftPtr(const bft::protobuf::BftMessage& bft_msg) {
    BftInterfacePtr bft_ptr = std::make_shared<TxBft>();
    bft_ptr->set_gid(bft_msg.gid());
    bft_ptr->set_network_id(bft_msg.net_id());
    bft_ptr->set_pool_index(bft_msg.pool_index());
    bft_ptr->set_status(kBftPrepare);
    bft_ptr->set_member_count(
        elect::ElectManager::Instance()->GetMemberCount(bft_msg.net_id()));
    AddBft(bft_ptr);
    return bft_ptr;
}

int BftManager::CreateGenisisBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
//     if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
//         CreateRootGenisisBlock();
//     } else {
//         CreateConsenseGenisisBlock();
//     }

    return kBftSuccess;
}

bool BftManager::VerifyAggSignWithMembers(
        const elect::MembersPtr& members,
        const bft::protobuf::Block& block) {
    auto block_hash = GetBlockHash(block);
    for (int32_t i = 0; i < block.bitmap_size(); ++i) {
        block_hash += std::to_string(block.bitmap(i));
    }

    auto hash = common::Hash::Hash256(block_hash);
    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq(block.bls_agg_sign_x().c_str());
    sign.Y = libff::alt_bn128_Fq(block.bls_agg_sign_y().c_str());
    sign.Z = libff::alt_bn128_Fq::one();
    uint32_t t = common::GetSignerCount(members->size());
    uint32_t n = members->size();
    if (bls::BlsManager::Instance()->Verify(
            t,
            n,
            elect::ElectManager::Instance()->GetCommonPublicKey(
            block.electblock_height(),
            block.network_id()),
            sign,
            hash) != bls::kBlsSuccess) {
        auto tmp_block_hash = GetBlockHash(block);
        BFT_ERROR("VerifyBlsAggSignature agg sign failed!prepare hash: %s, agg sign hash: %s,"
            "t: %u, n: %u, elect height: %lu, network id: %u, agg x: %s, agg y: %s",
            common::Encode::HexEncode(tmp_block_hash).c_str(),
            common::Encode::HexEncode(hash).c_str(),
            t, n, block.electblock_height(), block.network_id(),
            block.bls_agg_sign_x().c_str(),
            block.bls_agg_sign_y().c_str());
        return false;
    }

//     if (bls::BlsSign::Verify(
//             t,
//             n,
//             sign,
//             hash,
//             elect::ElectManager::Instance()->GetCommonPublicKey(
//             block.electblock_height(),
//             block.network_id())) != bls::kBlsSuccess) {
//         auto tmp_block_hash = GetBlockHash(block);
//         BFT_ERROR("VerifyBlsAggSignature agg sign failed!prepare hash: %s, agg sign hash: %s,"
//             "t: %u, n: %u, elect height: %lu, network id: %u, agg x: %s, agg y: %s",
//             common::Encode::HexEncode(tmp_block_hash).c_str(),
//             common::Encode::HexEncode(hash).c_str(),
//             t, n, block.electblock_height(), block.network_id(),
//             block.bls_agg_sign_x().c_str(),
//             block.bls_agg_sign_y().c_str());
//         return false;
//     }

    return true;
}

bool BftManager::AggSignValid(
        uint32_t thread_idx,
        uint32_t type,
        const bft::protobuf::Block& block) {
    assert(thread_idx < transport::kMessageHandlerThreadCount);
    if (!block.has_bls_agg_sign_x() ||
            !block.has_bls_agg_sign_y() ||
            block.bitmap_size() <= 0) {
        BFT_ERROR("commit must have agg sign. block.has_bls_agg_sign_y(): %d,"
            "block.has_bls_agg_sign_y(): %d, block.bitmap_size(): %u",
            block.has_bls_agg_sign_x(), block.has_bls_agg_sign_y(), block.bitmap_size());
        return false;
    }

    auto members = elect::ElectManager::Instance()->GetNetworkMembersWithHeight(
        block.electblock_height(),
        block.network_id());
    if (members == nullptr) {
        // The election block arrives later than the consensus block,
        // causing the aggregate signature verification to fail
        // add to waiting verify pool.
        BFT_ERROR("get members failed height: %lu", block.electblock_height());
        auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
        waiting_verify_block_queue_[thread_idx].push(
            std::make_shared<WaitingBlockItem>(block_ptr, type));
        return false;
    }

    return VerifyAggSignWithMembers(members, block);
}

void BftManager::HandleRootTxBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
//     if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
//         BFT_ERROR("root congress don't handle this message.");
//         return;
//     }

    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("tx_bft.ParseFromString failed.");
        return;
    }

    if (!(tx_bft.has_to_tx() && tx_bft.to_tx().has_block())) {
        BFT_ERROR("tx_bft tx_bft.has_to_tx() && tx_bft.to_tx().has_block() failed.");
        return;
    }

    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        BFT_ERROR("HandleToAccountTxBlock failed mem index invalid: %u", bft_msg.member_index());
        return;
    }

    if (!AggSignValid(header.thread_idx(), kRootBlock, tx_bft.to_tx().block())) {
        BFT_ERROR("root block agg sign verify failed! height: %lu, type: %d",
            tx_bft.to_tx().block().height(),
            tx_bft.to_tx().block().tx_list(0).type());
        return;
    }
 
    BlockPtr block_ptr = nullptr;
    HandleVerifiedBlock(header.thread_idx(), kRootBlock, tx_bft.to_tx().block(), block_ptr);
}

elect::MembersPtr BftManager::GetNetworkMembers(uint32_t network_id) {
    return elect::ElectManager::Instance()->GetNetworkMembers(network_id);
}

void BftManager::RootCommitAddNewAccount(
        const bft::protobuf::Block& block,
        db::DbWriteBach& db_batch) {
    auto& tx_list = block.tx_list();
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].status() != 0) {
            continue;
        }

        db::DbWriteBach db_batch;
        if (block::AccountManager::Instance()->AddNewAccount(
                tx_list[i],
                block.height(),
                block.hash(),
                db_batch) != block::kBlockSuccess) {
            continue;
        }

        auto st = db::Db::Instance()->Put(db_batch);
        if (!st.ok()) {
            exit(0);
        }
    }
}

void BftManager::HandleSyncBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        BFT_ERROR("HandleToAccountTxBlock failed mem index invalid: %u", bft_msg.member_index());
        return;
    }

    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("tx_bft.ParseFromString failed.");
        return;
    }

    if (!(tx_bft.has_to_tx() && tx_bft.to_tx().has_block())) {
        BFT_ERROR("tx_bft tx_bft.has_to_tx() && tx_bft.to_tx().has_block() failed.");
        return;
    }

    auto src_block = tx_bft.to_tx().block();
    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    if (!AggSignValid(header.thread_idx(), kSyncBlock, tx_bft.to_tx().block())) {
        BFT_ERROR("sync block agg sign verify failed!");
        return;
    }

    BlockPtr block_ptr = nullptr;
    HandleVerifiedBlock(header.thread_idx(), kSyncBlock, tx_bft.to_tx().block(), block_ptr);
}

void BftManager::HandleToAccountTxBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        BFT_ERROR("HandleToAccountTxBlock failed mem index invalid: %u", bft_msg.member_index());
        return;
    }

    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("tx_bft.ParseFromString failed.");
        return;
    }

    if (!(tx_bft.has_to_tx() && tx_bft.to_tx().has_block())) {
        BFT_ERROR("tx_bft tx_bft.has_to_tx() && tx_bft.to_tx().has_block() failed.");
        return;
    }

    auto src_block = tx_bft.to_tx().block();
    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    if (!AggSignValid(header.thread_idx(), kToBlock, tx_bft.to_tx().block())) {
        BFT_ERROR("ts block agg sign verify failed!");
        return;
    }

    BlockPtr block_ptr = nullptr;
    HandleVerifiedBlock(header.thread_idx(), kToBlock, tx_bft.to_tx().block(), block_ptr);
}

int BftManager::InitBft(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    uint32_t network_id = 0;
    if (!DispatchPool::Instance()->InitCheckTxValid(bft_msg)) {
        DHT_ERROR("invalid bft request, gid cover or new addr cover![%s]",
                common::Encode::HexEncode(bft_msg.gid()).c_str());
        return kBftError;
    }

    std::string tx_hash;
    if (VerifySignatureWithBftMessage(bft_msg, &tx_hash) != kBftSuccess) {
        BFT_ERROR("verify signature with bft message failed!");
        return kBftError;
    }

    int res = DispatchPool::Instance()->Dispatch(bft_msg, tx_hash);
    if (res != kBftSuccess) {
        BFT_ERROR("dispatch pool failed res[%d]!", res);
    }

    int32_t pool_mod_index = elect::ElectManager::Instance()->local_node_pool_mod_num();
    if (pool_mod_index < 0) {
        return kBftSuccess;
    }

    res = StartBft(bft_msg.gid(), pool_mod_index);
    if (res != kBftSuccess) {
        if (res != kBftNoNewTxs) {
            BFT_WARN("start [%s][%llu] failed![%d]",
                bft_msg.gid().c_str(),
                bft_msg.net_id(),
                res);
        }

        return res;
    }

    return kBftSuccess;
}

int BftManager::StartBft(const std::string& gid, int32_t pool_mod_index) {
    BftInterfacePtr bft_ptr = std::make_shared<TxBft>();
    if (bft_ptr->Init() != kBftSuccess) {
        BFT_ERROR("leader create bft failed!");
        return kBftError;
    }

    bft_ptr->set_gid(common::GlobalInfo::Instance()->gid());
    bft_ptr->set_network_id(common::GlobalInfo::Instance()->network_id());
    bft_ptr->set_randm_num(vss::VssManager::Instance()->EpochRandom());
    bft_ptr->set_member_count(elect::ElectManager::Instance()->GetMemberCount(
        common::GlobalInfo::Instance()->network_id()));
    std::string prepare_data;
    int leader_pre = LeaderPrepare(bft_ptr, pool_mod_index);
    if (leader_pre != kBftSuccess) {
        if (bft_ptr->pool_index() < common::kInvalidPoolIndex) {
            bft_ptr->clear_item_index_vec();
            DispatchPool::Instance()->BftOver(bft_ptr);
        }

        return leader_pre;
    }

    BFT_DEBUG("this node is leader and start bft: %s",
        common::Encode::HexEncode(bft_ptr->gid()).c_str());
    return kBftSuccess;
}

int BftManager::AddBft(BftInterfacePtr& bft_ptr) {
    std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
    auto iter = bft_hash_map_.find(bft_ptr->gid());
    if (iter != bft_hash_map_.end()) {
        return kBftAdded;
    }

    bft_hash_map_[bft_ptr->gid()] = bft_ptr;
//     BFT_DEBUG("add bft and now size: %d", bft_hash_map_.size());
    return kBftSuccess;
}

BftInterfacePtr BftManager::GetBft(const std::string& gid) {
    std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
    auto iter = bft_hash_map_.find(gid);
    if (iter == bft_hash_map_.end()) {
        return nullptr;
    }

    return iter->second;
}

void BftManager::RemoveBft(const std::string& gid, bool remove_tx) {
    BftInterfacePtr bft_ptr{ nullptr };
    {
        std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
        auto iter = bft_hash_map_.find(gid);
        if (iter != bft_hash_map_.end()) {
            bft_ptr = iter->second;
            bft_hash_map_.erase(iter);
        }
    }

    if (bft_ptr && !remove_tx) {
        // don't remove tx
        bft_ptr->clear_item_index_vec();
    }

    if (bft_ptr) {
        DispatchPool::Instance()->BftOver(bft_ptr);
    }
}

int BftManager::LeaderPrepare(BftInterfacePtr& bft_ptr, int32_t pool_mod_idx) {
    std::string prepare_data;
    bft::protobuf::BftMessage bft_msg;
    int res = bft_ptr->Prepare(true, pool_mod_idx, bft_msg, &prepare_data);
    if (res != kBftSuccess || prepare_data.empty()) {
        return res;
    }

    uint32_t member_idx = bft_ptr->mem_manager_ptr()->GetMemberIndex(
        bft_ptr->network_id(),
        common::GlobalInfo::Instance()->id());
    if (member_idx == elect::kInvalidMemberIndex) {
        BFT_ERROR("get local member index invalid![%u] network id[%u], id[%s]",
            member_idx,
            bft_ptr->network_id(),
            common::Encode::HexEncode(common::GlobalInfo::Instance()->id()).c_str());
        return kBftError;
    }

    security::Signature leader_sig;
    if (!security::Schnorr::Instance()->Sign(
            bft_ptr->prepare_hash(),
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            leader_sig)) {
        BFT_ERROR("leader signature error.");
        return kBftError;
    }

    libff::alt_bn128_G1 sign;
    if (bls::BlsManager::Instance()->Sign(
            bft_ptr->min_aggree_member_count(),
            bft_ptr->member_count(),
            bft_ptr->local_sec_key(),
            bft_ptr->prepare_hash(),
            &sign) != bls::kBlsSuccess) {
        BFT_ERROR("leader signature error.");
        return kBftError;
    }

    auto& member_ptr = (*bft_ptr->members_ptr())[member_idx];
    uint32_t t = common::GetSignerCount(bft_ptr->members_ptr()->size());
    if (bls::BlsManager::Instance()->Verify(
            t,
            bft_ptr->members_ptr()->size(),
            member_ptr->bls_publick_key,
            sign,
            bft_ptr->prepare_hash()) != bls::kBlsSuccess) {
        BFT_ERROR("verify prepare hash error!");
        return kBftError;
    }

    bft_ptr->LeaderPrecommitOk(
        member_idx,
        bft_ptr->gid(),
        0,
        true,
        sign,
        common::GlobalInfo::Instance()->id());
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    if (dht_ptr == nullptr) {
        BFT_ERROR("this node has not joined consensus network[%u].", bft_ptr->network_id());
        return kBftError;
    }

    res = AddBft(bft_ptr);
    if (res != kBftSuccess) {
        return res;
    }

    auto local_node = dht_ptr->local_node();
    auto prepare_msg = std::make_shared<transport::protobuf::Header>();
    BftProto::LeaderCreatePrepare(
        local_node,
        prepare_data,
        bft_ptr,
        leader_sig,
        *prepare_msg);
    bft_ptr->set_leader_precommit_msg(prepare_msg);
    network::Route::Instance()->Send(*prepare_msg);
    bft_ptr->init_prepare_timeout();

    // (TODO): just for test
#ifdef TENON_UNITTEST
    leader_prepare_msg_ = *prepare_msg;
#endif
    return kBftSuccess;
}

int BftManager::BackupPrepare(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (bft_ptr->backup_prepare_msg() != nullptr) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            bft_msg.node_ip(), bft_msg.node_port(), 0, *bft_ptr->backup_prepare_msg());
        return kBftSuccess;
    }

    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto msg = std::make_shared<transport::protobuf::Header>();
    if (!bft_ptr->CheckLeaderPrepare(bft_msg)) {
        std::string res_data = std::to_string(kBftInvalidPackage) + ",-1";
        BftProto::BackupCreatePrepare(
            header,
            bft_msg,
            local_node,
            res_data,
            bft_ptr,
            false,
            *msg);
        RemoveBft(bft_ptr->gid(), false);
        BFT_ERROR("0 bft backup prepare failed! not agree bft gid: %s",
            common::Encode::HexEncode(bft_ptr->gid()).c_str());
    } else {
        std::string data;
        int prepare_res = bft_ptr->Prepare(false, -1, bft_msg, &data);
        if (prepare_res != kBftSuccess) {
            std::string res_data = std::to_string(prepare_res) + "," + data;
            BftProto::BackupCreatePrepare(
                header,
                bft_msg,
                local_node,
                res_data,
                bft_ptr,
                false,
                *msg);
            RemoveBft(bft_ptr->gid(), false);
            BFT_ERROR("1 bft backup prepare failed! not agree bft gid: %s",
                common::Encode::HexEncode(bft_ptr->gid()).c_str());
        } else {
            BftProto::BackupCreatePrepare(
                header,
                bft_msg,
                local_node,
                data,
                bft_ptr,
                true,
                *msg);
            BFT_ERROR("bft backup prepare success! agree bft gid: %s, from: %s:%d",
                common::Encode::HexEncode(bft_ptr->gid()).c_str(),
                bft_msg.node_ip().c_str(), bft_msg.node_port());
        }
    }

    if (!msg->has_data()) {
        BFT_ERROR("message set data failed!");
        return kBftError;
    }

    bft_ptr->set_status(kBftPreCommit);
    bft_ptr->set_backup_prepare_msg(msg);
    // send prepare to leader
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            bft_msg.node_ip(), bft_msg.node_port(), 0, *msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, *msg);
    }

#ifdef TENON_UNITTEST
    backup_prepare_msg_ = *msg;
#endif
    return kBftSuccess;
}

int BftManager::LeaderPrecommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
//     uint64_t time1 = common::TimeUtils::TimestampUs();
//     uint64_t time2;
//     uint64_t time3;
//     uint64_t time4;
//     uint64_t time5;
    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        BFT_ERROR("backup message member index invalid.");
        return kBftError;
    }

    if (bft_ptr->members_ptr()->size() <= bft_msg.member_index()) {
        BFT_ERROR("backup message member index invalid. %d", bft_msg.member_index());
        return kBftError;
    }

    auto& member_ptr = (*bft_ptr->members_ptr())[bft_msg.member_index()];
    if (member_ptr->public_ip.empty()) {
        member_ptr->public_ip = bft_msg.node_ip();
        member_ptr->public_port = bft_msg.node_port();
        BFT_DEBUG("set prepare node public ip: %u, index: %d", member_ptr->public_ip, bft_msg.member_index());
    }

    uint32_t t = common::GetSignerCount(bft_ptr->members_ptr()->size());
    if (!bls::IsValidBigInt(bft_msg.bls_sign_x()) || !bls::IsValidBigInt(bft_msg.bls_sign_y())) {
        BFT_ERROR("verify prepare hash error!");
        return kBftError;
    }

    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq(bft_msg.bls_sign_x().c_str());
    sign.Y = libff::alt_bn128_Fq(bft_msg.bls_sign_y().c_str());
    sign.Z = libff::alt_bn128_Fq::one();
    if (bls::BlsManager::Instance()->Verify(
            t,
            bft_ptr->members_ptr()->size(),
            member_ptr->bls_publick_key,
            sign,
            bft_ptr->prepare_hash()) != bls::kBlsSuccess) {
        auto failed_count = bft_ptr->add_prepare_verify_failed_count();
        if (failed_count >= bft_ptr->min_oppose_member_count() &&
                bft_ptr->elect_height() <
                elect::ElectManager::Instance()->latest_height(bft_ptr->network_id())) {
            BFT_DEBUG("elect height error, LeaderPrecommit RemoveBft kBftOppose"
                " pool_index: %u, bft: %s",
                bft_ptr->pool_index(), common::Encode::HexEncode(member_ptr->id).c_str());
            LeaderCallPrecommitOppose(bft_ptr);
            RemoveBft(bft_ptr->gid(), false);
        }

        BFT_ERROR("verify prepare hash error!");
        return kBftError;
    }

    int res = bft_ptr->LeaderPrecommitOk(
        bft_msg.member_index(),
        bft_ptr->gid(),
        header.id(),
        bft_msg.agree(),
        sign,
        member_ptr->id);
//     time3 = common::TimeUtils::TimestampUs();
    if (!bft_msg.agree()) {
        HandleOpposeNodeMsg(bft_msg, bft_ptr);
    }

//     BFT_ERROR("LeaderPrecommit res: %d", res);
    if (res == kBftAgree) {
        LeaderCallPrecommit(bft_ptr);
//         time4 = common::TimeUtils::TimestampUs();
    } else if (res == kBftOppose) {
        BFT_DEBUG("LeaderPrecommit RemoveBft kBftOppose pool_index: %u, bft: %s", bft_ptr->pool_index(), common::Encode::HexEncode(member_ptr->id).c_str());
        LeaderCallPrecommitOppose(bft_ptr);
        RemoveBft(bft_ptr->gid(), false);
//         time4 = common::TimeUtils::TimestampUs();
    } else {
        BFT_DEBUG("LeaderPrecommit %d waiting pool_index: %u, bft: %s", bft_msg.agree(), bft_ptr->pool_index(), common::Encode::HexEncode(member_ptr->id).c_str());
    }

//     BFT_DEBUG("bft: %s, LeaderPrecommit use time: %lu, %lu, %lu", common::Encode::HexEncode(member_ptr->id).c_str(), time2 - time1, time3 - time2, time4 - time3);
    // broadcast pre-commit to backups
    return kBftSuccess;
}

void BftManager::HandleOpposeNodeMsg(
        bft::protobuf::BftMessage& bft_msg,
        BftInterfacePtr& bft_ptr) {
    common::Split<> spliter(bft_msg.data().c_str(), ',', bft_msg.data().size());
    if (spliter.Count() < 2) {
        return;
    }
        
    int32_t res = 0;
    if (!common::StringUtil::ToInt32(spliter[0], &res)) {
        return;
    }

    // TODO: just use merkle-tree sync data, this will decrease performance
    if (res == kBftBlockPreHashError) {
        std::string pre_hash(bft_msg.data().c_str() + spliter.SubLen(0) + 1, 32);
        sync::KeyValueSync::Instance()->AddSync(
            common::GlobalInfo::Instance()->network_id(),
            pre_hash,
            sync::kSyncHighest);
//         BFT_DEBUG("add bft block pre hash sync: %s, bft gid: %s",
//             common::Encode::HexEncode(pre_hash).c_str(),
//             common::Encode::HexEncode(bft_ptr->gid()).c_str());
        return;
    }

    int32_t tx_index = -1;
    if (!common::StringUtil::ToInt32(spliter[1], &tx_index)) {
        return;
    }

    if (tx_index >= 0) {
        bft_ptr->AddInvalidTxIndex(tx_index);
    }
}

int BftManager::LeaderCallPrecommitOppose(BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    BftProto::LeaderCreatePreCommit(local_node, bft_ptr, false, msg);
    network::Route::Instance()->Send(msg);
    BFT_ERROR("LeaderCallPrecommitOppose gid: %s", common::Encode::HexEncode(bft_ptr->gid()).c_str());
#ifdef TENON_UNITTEST
    leader_precommit_msg_ = msg;
#endif
    return kBftSuccess;
}

int BftManager::LeaderCallPrecommit(BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign
    bft_ptr->init_precommit_timeout();
    libff::alt_bn128_G1 sign;
    if (bls::BlsManager::Instance()->Sign(
            bft_ptr->min_aggree_member_count(),
            bft_ptr->member_count(),
            bft_ptr->local_sec_key(),
            bft_ptr->precommit_hash(),
            &sign) != bls::kBlsSuccess) {
        BFT_ERROR("leader signature error.");
        return kBftError;
    }

    if (bft_ptr->LeaderCommitOk(
            elect::ElectManager::Instance()->local_node_member_index(),
            true,
            sign,
            common::GlobalInfo::Instance()->id()) != kBftWaitingBackup) {
        BFT_ERROR("leader commit failed!");
        RemoveBft(bft_ptr->gid(), false);
        return kBftError;
    }

    bft_ptr->set_status(kBftCommit);
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto precommit_msg = std::make_shared<transport::protobuf::Header>();  // msg;
    BftProto::LeaderCreatePreCommit(local_node, bft_ptr, true, *precommit_msg);
    bft_ptr->set_leader_precommit_msg(precommit_msg);
    network::Route::Instance()->Send(*precommit_msg);
#ifdef TENON_UNITTEST
    leader_precommit_msg_ = *precommit_msg;
#endif
    return kBftSuccess;
}

int BftManager::BackupPrecommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (bft_ptr->backup_precommit_msg() != nullptr) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            bft_msg.node_ip(), bft_msg.node_port(), 0, *bft_ptr->backup_precommit_msg());
        BFT_INFO("bft_ptr->backup_precommit_msg() error gid: %s",
            common::Encode::HexEncode(bft_ptr->gid()).c_str());
        return kBftSuccess;
    }

    std::string sign_hash;
    if (VerifyLeaderSignature(bft_ptr, bft_msg, &sign_hash) != kBftSuccess) {
        BFT_ERROR("check leader signature error!");
        return kBftError;
    }

    if (!bft_msg.agree()) {
        BFT_INFO("BackupPrecommit LeaderCallCommitOppose gid: %s",
            common::Encode::HexEncode(bft_ptr->gid()).c_str());
        RemoveBft(bft_ptr->gid(), false);
        return kBftSuccess;
    }

    if (VerifyBlsAggSignature(bft_ptr, bft_msg, bft_ptr->prepare_hash()) != kBftSuccess) {
        BFT_INFO("VerifyBlsAggSignature error gid: %s",
            common::Encode::HexEncode(bft_ptr->gid()).c_str());
        return kBftError;
    }

    // check prepare multi sign
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto msg = std::make_shared<transport::protobuf::Header>();
    std::string precommit_data;
    BftProto::BackupCreatePreCommit(
        header,
        bft_msg,
        bft_ptr,
        local_node,
        precommit_data,
        true,
        sign_hash,
        *msg);
    if (!msg->has_data()) {
        BFT_ERROR("BackupCreatePreCommit not has data.");
        return kBftError;
    }

    bft_ptr->set_status(kBftCommit);
    bft_ptr->set_backup_precommit_msg(msg);
    // send pre-commit to leader
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            bft_msg.node_ip(), bft_msg.node_port(), 0, *msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, *msg);
    }

#ifdef TENON_UNITTEST
    backup_precommit_msg_ = *msg;
#endif
    BFT_DEBUG("BackupPrecommit success.");
    return kBftSuccess;
}

int BftManager::LeaderCommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
//     uint64_t time1 = common::TimeUtils::TimestampUs();
//     uint64_t time2;
//     uint64_t time3;
//     uint64_t time4;
//     uint64_t time5;

    if (!bft_ptr->this_node_is_leader()) {
        BFT_ERROR("check leader error.");
        return kBftError;
    }

    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        BFT_ERROR("mem_index == elect::kInvalidMemberIndex.");
        return kBftError;
    }

    if (bft_ptr->members_ptr()->size() <= bft_msg.member_index()) {
        return kBftError;
    }

    uint32_t t = common::GetSignerCount(bft_ptr->members_ptr()->size());
    if (!bls::IsValidBigInt(bft_msg.bls_sign_x()) || !bls::IsValidBigInt(bft_msg.bls_sign_y())) {
        BFT_ERROR("verify prepare hash error!");
        return kBftError;
    }

    auto& member_ptr = (*bft_ptr->members_ptr())[bft_msg.member_index()];
    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq(bft_msg.bls_sign_x().c_str());
    sign.Y = libff::alt_bn128_Fq(bft_msg.bls_sign_y().c_str());
    sign.Z = libff::alt_bn128_Fq::one();
    if (bls::BlsManager::Instance()->Verify(
            t,
            bft_ptr->members_ptr()->size(),
            member_ptr->bls_publick_key,
            sign,
            bft_ptr->precommit_hash()) != bls::kBlsSuccess) {
        BFT_ERROR("verify precommit hash error!");
        return kBftError;
    }

    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        return kBftError;
    }

    if (bft_ptr->members_ptr()->size() <= bft_msg.member_index()) {
        return kBftError;
    }

//     time3 = common::TimeUtils::TimestampUs();
    int res = bft_ptr->LeaderCommitOk(
        bft_msg.member_index(),
        bft_msg.agree(),
        sign,
        member_ptr->id);
//     time4 = common::TimeUtils::TimestampUs();
    if (res == kBftAgree) {
        LeaderCallCommit(header, bft_ptr);
//         time5 = common::TimeUtils::TimestampUs();
    } else if (res == kBftOppose) {
//         BFT_DEBUG("LeaderCommit RemoveBft kBftOppose pool_index: %u", bft_ptr->pool_index());
        LeaderCallCommitOppose(header, bft_ptr);
        RemoveBft(bft_ptr->gid(), false);
//         time5 = common::TimeUtils::TimestampUs();
    }

//     BFT_DEBUG("bft: %s, LeaderPrecommit use time: %lu, %lu, %lu, %lu", common::Encode::HexEncode(member_ptr->id).c_str(), time2 - time1, time3 - time2, time4 - time3, time5 - time4);
    return kBftSuccess;
}

int BftManager::LeaderCallCommitOppose(
        const transport::protobuf::Header& header,
        BftInterfacePtr& bft_ptr) {
auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    BftProto::LeaderCreateCommit(local_node, bft_ptr, false, msg);
    if (!msg.has_data()) {
        BFT_ERROR("leader create commit message failed!");
        return kBftError;
    }

    bft_ptr->set_status(kBftCommited);
    network::Route::Instance()->Send(msg);
    LeaderBroadcastToAcc(bft_ptr, true);
    BFT_ERROR("LeaderCallCommitOppose gid: %s", common::Encode::HexEncode(bft_ptr->gid()).c_str());
#ifdef TENON_UNITTEST
    leader_commit_msg_ = msg;
#endif
//     BFT_DEBUG("LeaderCommit success waiting pool_index: %u, bft gid: %s",
//         bft_ptr->pool_index(), common::Encode::HexEncode(bft_ptr->gid()).c_str());
    return kBftSuccess;}

int BftManager::LeaderCallCommit(
        const transport::protobuf::Header& header,
        BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign and leader commit
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    BftProto::LeaderCreateCommit(local_node, bft_ptr, true, msg);
    if (!msg.has_data()) {
        BFT_ERROR("leader create commit message failed!");
        return kBftError;
    }

    auto& tenon_block = bft_ptr->prpare_block();
    tenon_block->set_pool_index(bft_ptr->pool_index());
    const auto& prepare_bitmap_data = bft_ptr->prepare_bitmap().data();
    for (uint32_t i = 0; i < prepare_bitmap_data.size(); ++i) {
        tenon_block->add_bitmap(prepare_bitmap_data[i]);
    }

    const auto& commit_bitmap_data = bft_ptr->precommit_bitmap().data();
    for (uint32_t i = 0; i < commit_bitmap_data.size(); ++i) {
        tenon_block->add_commit_bitmap(commit_bitmap_data[i]);
    }

    auto& bls_commit_sign = bft_ptr->bls_commit_agg_sign();
    tenon_block->set_bls_agg_sign_x(
        BLSutils::ConvertToString<libff::alt_bn128_Fq>(bls_commit_sign->X));
    tenon_block->set_bls_agg_sign_y(
        BLSutils::ConvertToString<libff::alt_bn128_Fq>(bls_commit_sign->Y));
    assert(tenon_block->bitmap_size() > 0);
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (tenon_block->tx_list_size() == 1 &&
                (tenon_block->tx_list(0).type() == common::kConsensusFinalStatistic ||
                tenon_block->tx_list(0).type() == common::kConsensusRootElectShard ||
                tenon_block->tx_list(0).type() == common::kConsensusRootTimeBlock)) {
        } else {
            db::DbWriteBach db_batch;
            RootCommitAddNewAccount(*tenon_block, db_batch);
            auto st = db::Db::Instance()->Put(db_batch);
            if (!st.ok()) {
                exit(0);
            }
        }
    }

    auto queue_item_ptr = std::make_shared<BlockToDbItem>(bft_ptr->prpare_block());
    if (block::AccountManager::Instance()->AddBlockItemToCache(
            queue_item_ptr->block_ptr,
            queue_item_ptr->db_batch) != block::kBlockSuccess) {
        BFT_ERROR("leader add block to db failed!");
        return kBftError;
    }

    BFT_DEBUG("VerifyBlsAggSignature agg sign success!prepare hash: %s, agg sign hash: %s,"
        "t: %u, n: %u, elect height: %lu, network id: %u, agg x: %s, agg y: %s",
        common::Encode::HexEncode(bft_ptr->prepare_hash()).c_str(),
        common::Encode::HexEncode(bft_ptr->precommit_hash()).c_str(),
        bft_ptr->min_aggree_member_count(), bft_ptr->member_count(),
        tenon_block->electblock_height(), tenon_block->network_id(),
        tenon_block->bls_agg_sign_x().c_str(),
        tenon_block->bls_agg_sign_y().c_str());
    block_queue_[header.thread_idx()].push(queue_item_ptr);
    bft_ptr->set_status(kBftCommited);
    network::Route::Instance()->Send(msg);
    LeaderBroadcastToAcc(bft_ptr, true);
    assert(bft_ptr->prpare_block()->bitmap_size() == tenon_block->bitmap_size());
    RemoveBft(bft_ptr->gid(), true);
#ifdef TENON_UNITTEST
    leader_commit_msg_ = msg;
#endif
    BFT_DEBUG("LeaderCommit success waiting pool_index: %u, bft gid: %s",
        bft_ptr->pool_index(), common::Encode::HexEncode(bft_ptr->gid()).c_str());
    return kBftSuccess;
}

// only genesis call once
int BftManager::AddGenisisBlock(const std::shared_ptr<bft::protobuf::Block>& genesis_block) {
    db::DbWriteBach db_batch;
    if (block::BlockManager::Instance()->AddNewBlock(genesis_block, db_batch, true) != block::kBlockSuccess) {
        BFT_ERROR("leader add block to db failed!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftManager::BackupCommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    std::string sign_hash;
    if (VerifyLeaderSignature(bft_ptr, bft_msg, &sign_hash) != kBftSuccess) {
        BFT_ERROR("check leader signature error!");
        return kBftError;
    }

    if (!bft_msg.agree()) {
        BFT_ERROR("BackupCommit LeaderCallCommitOppose gid: %s",
            common::Encode::HexEncode(bft_ptr->gid()).c_str());
        RemoveBft(bft_ptr->gid(), false);
        return kBftSuccess;
    }
    
    if (bft_ptr->precommit_hash().empty()) {
        return kBftError;
    }

    if (VerifyBlsAggSignature(bft_ptr, bft_msg, bft_ptr->precommit_hash()) != kBftSuccess) {
        return kBftError;
    }

    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    std::string commit_data;
    if (bft_ptr->Commit(false, commit_data) != kBftSuccess) {
        BFT_ERROR("bft backup commit failed!");
    }

    if (!bft_ptr->prpare_block()) {
        BFT_ERROR("bft_ptr->prpare_block failed!");
        return kBftError;
    }

    auto& tenon_block = bft_ptr->prpare_block();
//     tenon_block->set_agg_sign_challenge(bft_msg.agg_sign_challenge());
//     tenon_block->set_agg_sign_response(bft_msg.agg_sign_response());
    tenon_block->set_pool_index(bft_ptr->pool_index());
    tenon_block->set_bls_agg_sign_x(bft_msg.bls_sign_x());
    tenon_block->set_bls_agg_sign_y(bft_msg.bls_sign_y());
    for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
        tenon_block->add_bitmap(bft_msg.bitmap(i));
    }

    for (int32_t i = 0; i < bft_msg.commit_bitmap_size(); ++i) {
        tenon_block->add_commit_bitmap(bft_msg.commit_bitmap(i));
    }

    assert(tenon_block->bitmap_size() > 0);
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (tenon_block->tx_list_size() == 1 &&
                (tenon_block->tx_list(0).type() == common::kConsensusFinalStatistic ||
                tenon_block->tx_list(0).type() == common::kConsensusRootElectShard ||
                tenon_block->tx_list(0).type() == common::kConsensusRootTimeBlock)) {
        } else {
            db::DbWriteBach db_batch;
            RootCommitAddNewAccount(*tenon_block, db_batch);
            auto st = db::Db::Instance()->Put(db_batch);
            if (!st.ok()) {
                exit(0);
            }
        }
    }

    auto queue_item_ptr = std::make_shared<BlockToDbItem>(bft_ptr->prpare_block());
    if (block::AccountManager::Instance()->AddBlockItemToCache(
            queue_item_ptr->block_ptr,
            queue_item_ptr->db_batch) != block::kBlockSuccess) {
        BFT_ERROR("backup add block to db failed!");
        return kBftError;
    }

    block_queue_[header.thread_idx()].push(queue_item_ptr);
    bft_ptr->set_status(kBftCommited);
    assert(bft_ptr->prpare_block()->bitmap_size() == tenon_block->bitmap_size());
    BFT_DEBUG("BackupCommit success waiting pool_index: %u, bft gid: %s",
        bft_ptr->pool_index(), common::Encode::HexEncode(bft_ptr->gid()).c_str());
    LeaderBroadcastToAcc(bft_ptr, false);
    RemoveBft(bft_ptr->gid(), true);
    // start new bft
    return kBftSuccess;
}

void BftManager::LeaderBroadcastToAcc(BftInterfacePtr& bft_ptr, bool is_bft_leader) {
    // broadcast to this consensus shard and waiting pool shard
    if (!is_bft_leader && !elect::ElectManager::Instance()->LocalNodeIsSuperLeader()) {
        return;
    }

    const std::shared_ptr<bft::protobuf::Block>& block_ptr = bft_ptr->prpare_block();
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    if (!dht_ptr) {
        assert(false);
        return;
    }

    auto local_node = dht_ptr->local_node();
    // consensus pool sync by pull in bft step commit
    //
    // waiting pool sync by push
    {
        transport::protobuf::Header msg;
        BftProto::CreateLeaderBroadcastToAccount(
            local_node,
            common::GlobalInfo::Instance()->network_id() + network::kConsensusWaitingShardOffset,
            common::kBftMessage,
            kBftSyncBlock,
            false,
            block_ptr,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
        }
    }

    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (block_ptr->tx_list_size() == 1 &&
                block_ptr->tx_list(0).type() == common::kConsensusFinalStatistic) {
            return;
        }

        transport::protobuf::Header msg;
        BftProto::CreateLeaderBroadcastToAccount(
            local_node,
            network::kNodeNetworkId,
            common::kBftMessage,
            kBftRootBlock,
            true,
            block_ptr,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
            network::Route::Instance()->SendToLocal(msg);
        }
#ifdef TENON_UNITTEST
        root_leader_broadcast_msg_ = msg;
#endif
        return;
    }

    std::set<uint32_t> broadcast_nets;
    auto tx_list = block_ptr->tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].status() == kBftSuccess &&
                tx_list[i].type() == common::kConsensusFinalStatistic) {
            broadcast_nets.insert(network::kRootCongressNetworkId);
            continue;
        }

        // contract must unlock caller
        if (tx_list[i].status() != kBftSuccess &&
                (tx_list[i].type() != common::kConsensusCreateContract &&
                tx_list[i].type() != common::kConsensusCallContract)) {
            continue;
        }

        if (tx_list[i].has_to() && !tx_list[i].to_add() &&
                tx_list[i].type() != common::kConsensusCallContract &&
                tx_list[i].type() != common::kConsensusCreateContract) {
            auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
                tx_list[i].to());
            uint32_t network_id = network::kRootCongressNetworkId;
            if (account_ptr != nullptr) {
                account_ptr->GetConsensuseNetId(&network_id);
            }

            broadcast_nets.insert(network_id);
        }

        if (tx_list[i].type() == common::kConsensusCallContract ||
                tx_list[i].type() == common::kConsensusCreateContract) {
            std::string id = "";
            if (tx_list[i].call_contract_step() == contract::kCallStepCallerInited) {
                id = tx_list[i].to();
            } else if (tx_list[i].call_contract_step() == contract::kCallStepContractCalled) {
                id = tx_list[i].from();
            } else {
                continue;
            }
             
            if (id.empty()) {
                continue;
            }

            auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(id);
            uint32_t network_id = network::kRootCongressNetworkId;
            if (account_ptr != nullptr) {
                account_ptr->GetConsensuseNetId(&network_id);
            }

            broadcast_nets.insert(network_id);
        }
    }

    for (auto iter = broadcast_nets.begin(); iter != broadcast_nets.end(); ++iter) {
        transport::protobuf::Header msg;
        BftProto::CreateLeaderBroadcastToAccount(
            local_node,
            *iter,
            common::kBftMessage,
            kBftToTxInit,
            false,
            block_ptr,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
            network::Route::Instance()->SendToLocal(msg);
        }
#ifdef TENON_UNITTEST
        to_leader_broadcast_msg_ = msg;
#endif
    }
}

void BftManager::CheckTimeout() {
    std::vector<BftInterfacePtr> timeout_vec;
    std::unordered_map<std::string, BftInterfacePtr> bft_hash_map;
    {
        std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
        bft_hash_map = bft_hash_map_;
    }

    for (auto iter = bft_hash_map.begin(); iter != bft_hash_map.end(); ++iter) {
        int timeout_res = iter->second->CheckTimeout();
        switch (timeout_res) {
        case kTimeout: {
            {
                std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
                auto riter = bft_hash_map_.find(iter->first);
                if (riter != bft_hash_map_.end()) {
                    bft_hash_map_.erase(riter);
                }
            }

                // don't remove tx
            iter->second->clear_item_index_vec();
            DispatchPool::Instance()->BftOver(iter->second);
//             BFT_DEBUG("bft timeout remove: %s", common::Encode::HexEncode(iter->first).c_str());
            break;
        }
        case kTimeoutCallPrecommit: {
            iter->second->AddBftEpoch();
            LeaderCallPrecommit(iter->second);
            break;
        }
        case kTimeoutNormal:
        case kTimeoutWaitingBackup:
            break;
        default:
            break;
        }
    }

    DispatchPool::Instance()->CheckTimeoutTx();
    timeout_tick_.CutOff(
            kBftTimeoutCheckPeriod,
            std::bind(&BftManager::CheckTimeout, this));
}

int BftManager::VerifySignatureWithBftMessage(
        const bft::protobuf::BftMessage& bft_msg,
        std::string* tx_hash) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("protobuf::TxBft ParseFromString failed!");
        return kBftError;
    }

    auto pubkey = security::PublicKey(bft_msg.pubkey());
    auto sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    *tx_hash = GetTxMessageHash(tx_bft.new_tx());
    if (!security::Schnorr::Instance()->Verify(*tx_hash, sign, pubkey)) {
        BFT_ERROR("check signature error![pubkey: %s][hash: %s][data: %s][challen: %s][res: %s]",
            common::Encode::HexEncode(bft_msg.pubkey()).c_str(),
            common::Encode::HexEncode(*tx_hash).c_str(),
            common::Encode::HexEncode(bft_msg.data()).c_str(),
            common::Encode::HexEncode(bft_msg.sign_challenge()).c_str(),
            common::Encode::HexEncode(bft_msg.sign_response()).c_str());
        return kBftError;
    }

    return kBftSuccess;
}

int BftManager::VerifySignature(
        const elect::BftMemberPtr& mem_ptr,
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& sha128,
        security::Signature& sign) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    if (!security::Schnorr::Instance()->Verify(sha128, sign, mem_ptr->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }

    return kBftSuccess;
}
// 
// int BftManager::VerifyBlockSignature(
//         uint32_t mem_index,
//         const bft::protobuf::BftMessage& bft_msg,
//         const bft::protobuf::Block& tx_block,
//         security::Signature& sign) {
//     if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
//         BFT_ERROR("backup has no sign");
//         return kBftError;
//     }
// 
//     sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
//     auto mem_ptr = elect::ElectManager::Instance()->GetMember(
//         tx_block.electblock_height(),
//         bft_msg.net_id(),
//         mem_index);
//     if (!mem_ptr) {
//         return kBftError;
//     }
// 
//     auto block_hash = GetBlockHash(tx_block);
//     if (block_hash != tx_block.hash()) {
//         return kBftError;
//     }
// 
//     if (!security::Schnorr::Instance()->Verify(block_hash, sign, mem_ptr->pubkey)) {
//         BFT_ERROR("check signature error!");
//         return kBftError;
//     }
// 
//     return kBftSuccess;
// }

int BftManager::VerifyLeaderSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg,
        std::string* sign_hash) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    auto sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    *sign_hash = bft_ptr->prepare_hash();
    if (bft_msg.agree()) {
        if (bft_msg.bft_step() == kBftCommit) {
            std::string msg_hash_src = bft_ptr->prepare_hash();
            for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
                msg_hash_src += std::to_string(bft_msg.bitmap(i));
            }

            msg_hash_src = common::Hash::Hash256(msg_hash_src);
            for (int32_t i = 0; i < bft_msg.commit_bitmap_size(); ++i) {
                msg_hash_src += std::to_string(bft_msg.commit_bitmap(i));
            }

            *sign_hash = common::Hash::Hash256(msg_hash_src);
        } else if (bft_msg.bft_step() == kBftPreCommit) {
            std::string msg_hash_src = bft_ptr->prepare_hash();
            for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
                msg_hash_src += std::to_string(bft_msg.bitmap(i));
            }

            *sign_hash = common::Hash::Hash256(msg_hash_src);
            bft_ptr->set_precoimmit_hash(*sign_hash);
        }
    }

    if (!security::Schnorr::Instance()->Verify(
            *sign_hash,
            sign,
            bft_ptr->leader_mem_ptr()->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftManager::VerifyBlsAggSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& sign_hash) {
    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq(bft_msg.bls_sign_x().c_str());
    sign.Y = libff::alt_bn128_Fq(bft_msg.bls_sign_y().c_str());
    sign.Z = libff::alt_bn128_Fq::one();
    uint32_t t = common::GetSignerCount(bft_ptr->members_ptr()->size());
    uint32_t n = bft_ptr->members_ptr()->size();
    if (bls::BlsManager::Instance()->Verify(
            t,
            n,
            elect::ElectManager::Instance()->GetCommonPublicKey(
            bft_ptr->elect_height(),
            bft_ptr->network_id()),
            sign,
            sign_hash) != bls::kBlsSuccess) {
        BFT_ERROR("VerifyBlsAggSignature agg sign failed!");
        return kBftError;
    }
//     if (bls::BlsSign::Verify(
//             t,
//             n,
//             sign,
//             sign_hash,
//             elect::ElectManager::Instance()->GetCommonPublicKey(
//             bft_ptr->elect_height(),
//             bft_ptr->network_id())) != bls::kBlsSuccess) {
//         BFT_ERROR("VerifyBlsAggSignature agg sign failed!");
//         return kBftError;
//     }

    return kBftSuccess;
}


int BftManager::AddKeyValueSyncBlock(
        const transport::protobuf::Header& header,
        std::shared_ptr<bft::protobuf::Block>& block_ptr) {
    auto queue_item_ptr = std::make_shared<BlockToDbItem>(block_ptr);
    if (block::AccountManager::Instance()->AddBlockItemToCache(
            queue_item_ptr->block_ptr,
            queue_item_ptr->db_batch) != block::kBlockSuccess) {
        BFT_ERROR("leader add block to db failed!");
        return kBftError;
    }

    block_queue_[header.thread_idx()].push(queue_item_ptr);
    return kBftSuccess;
}

void BftManager::BlockToDb() {
    for (uint32_t i = 0; i < transport::kMessageHandlerThreadCount; ++i) {
        while (block_queue_[i].size() > 0) {
            BlockToDbItemPtr db_item_ptr;
            if (block_queue_[i].pop(&db_item_ptr)) {
                //
                block::BlockManager::Instance()->AddNewBlock(
                    db_item_ptr->block_ptr,
                    db_item_ptr->db_batch,
                    false);
            }
        }
    }

    block_to_db_tick_.CutOff(kBlockToDbPeriod, std::bind(&BftManager::BlockToDb, this));
}

void BftManager::HandleSyncWaitingBlock(
        uint32_t thread_idx,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr) {
    auto tmp_block_ptr = block_ptr;
    if (tmp_block_ptr == nullptr) {
        tmp_block_ptr = std::make_shared<bft::protobuf::Block>(block);
    }

    if (thread_idx < transport::kMessageHandlerThreadCount) {
        auto queue_item_ptr = std::make_shared<BlockToDbItem>(tmp_block_ptr);
        if (block::AccountManager::Instance()->AddBlockItemToCache(
            queue_item_ptr->block_ptr,
            queue_item_ptr->db_batch) != block::kBlockSuccess) {
            BFT_ERROR("leader add block to db failed!");
            return;
        }

        block_queue_[thread_idx].push(queue_item_ptr);
    } else {
        db::DbWriteBach db_batch;
        block::AccountManager::Instance()->AddBlockItemToCache(tmp_block_ptr, db_batch);
        block::AccountManager::Instance()->AddBlockItemToDb(tmp_block_ptr, db_batch);
        db::Db::Instance()->Put(db_batch);
    }
    
    auto& tx_list = block.tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        DispatchPool::Instance()->RemoveTx(
            block.pool_index(),
            tx_list[i].to_add(),
            tx_list[i].type(),
            tx_list[i].call_contract_step(),
            tx_list[i].gid());
    }
}

void BftManager::HandleToWaitingBlock(
        uint32_t thread_idx,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr) {
    bool just_broadcast = false;
    auto& tx_list = block.tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].type() == common::kConsensusFinalStatistic) {
            bft::protobuf::TxInfo tx_info;
            if (elect::ElectManager::Instance()->CreateElectTransaction(
                    tx_list[i].network_id(),
                    block.height(),
                    tx_list[i],
                    tx_info) != elect::kElectSuccess) {
                BFT_ERROR("create elect transaction error!");
                continue;
            }

            if (DispatchPool::Instance()->Dispatch(tx_info) != kBftSuccess) {
                BFT_ERROR("dispatch pool failed!");
            }

            continue;
        }

        if (tx_list[i].to().empty()) {
            continue;
        }

        if (tx_list[i].status() != 0 &&
                tx_list[i].type() != common::kConsensusCreateContract &&
                tx_list[i].type() != common::kConsensusCallContract) {
            BFT_ERROR("status error!");
            continue;
        }

        auto new_tx = tx_list[i];
        new_tx.set_to_add(true);
        if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
            auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(new_tx.to());
            if (account_ptr != nullptr) {
                // root just create account address and assignment consensus network id
                just_broadcast = true;
                BFT_ERROR("account address exists error and broadcast it from [%s] to [%s]!",
                    common::Encode::HexEncode(new_tx.from()).c_str(),
                    common::Encode::HexEncode(new_tx.to()).c_str());
                continue;
            }

            if (new_tx.amount() <= 0 &&
                    new_tx.type() != common::kConsensusCreateContract) {
                BFT_ERROR("transfer amount error!");
                continue;
            }
        }

        if (DispatchPool::Instance()->Dispatch(new_tx) != kBftSuccess) {
            BFT_ERROR("dispatch pool failed!");
        }
    }

    if (just_broadcast) {
//         LeaderBroadcastToAcc(std::make_shared<bft::protobuf::Block>(src_block));
    }

    int32_t pool_mod_index = elect::ElectManager::Instance()->local_node_pool_mod_num();
    if (pool_mod_index >= 0) {
        StartBft("", pool_mod_index);
    }
}

void BftManager::HandleRootWaitingBlock(
        uint32_t thread_idx,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr) {
    auto& tx_list = block.tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        DispatchPool::Instance()->RemoveTx(
            block.pool_index(),
            tx_list[i].to_add(),
            tx_list[i].type(),
            tx_list[i].call_contract_step(),
            tx_list[i].gid());
    }

    if (tx_list.size() == 1 && IsRootSingleBlockTx(tx_list[0].type())) {
        auto tmp_block_ptr = block_ptr;
        if (tmp_block_ptr == nullptr) {
            tmp_block_ptr = std::make_shared<bft::protobuf::Block>(block);
        }

        if (thread_idx < transport::kMessageHandlerThreadCount) {
            auto queue_item_ptr = std::make_shared<BlockToDbItem>(tmp_block_ptr);
            if (block::AccountManager::Instance()->AddBlockItemToCache(
                queue_item_ptr->block_ptr,
                queue_item_ptr->db_batch) != block::kBlockSuccess) {
                BFT_ERROR("leader add block to db failed!");
            }

            block_queue_[thread_idx].push(queue_item_ptr);
        } else {
            db::DbWriteBach db_batch;
            block::AccountManager::Instance()->AddBlockItemToCache(tmp_block_ptr, db_batch);
            block::AccountManager::Instance()->AddBlockItemToDb(tmp_block_ptr, db_batch);
            db::Db::Instance()->Put(db_batch);
        }
        
        return;
    }

    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].status() != 0) {
            continue;
        }

        db::DbWriteBach db_batch;
        if (block::AccountManager::Instance()->AddNewAccount(
                tx_list[i],
                block.height(),
                block.hash(),
                db_batch) != block::kBlockSuccess) {
            continue;
        }

        auto st = db::Db::Instance()->Put(db_batch);
        if (!st.ok()) {
            exit(0);
        }

        if (DispatchPool::Instance()->Dispatch(tx_list[i]) != kBftSuccess) {
            BFT_ERROR("dispatch pool failed!");
        }
    }

    int32_t pool_mod_index = elect::ElectManager::Instance()->local_node_pool_mod_num();
    if (pool_mod_index >= 0) {
        StartBft("", pool_mod_index);
    }
}

void BftManager::HandleVerifiedBlock(
        uint32_t thread_idx,
        uint32_t type,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr) {
    switch (type) {
    case kRootBlock:
        HandleRootWaitingBlock(thread_idx, block, block_ptr);
        break;
    case kSyncBlock:
        HandleSyncWaitingBlock(thread_idx, block, block_ptr);
        break;
    case kToBlock:
        HandleToWaitingBlock(thread_idx, block, block_ptr);
        break;
    default:
        break;
    }
}

void BftManager::VerifyWaitingBlock() {
    for (uint32_t i = 0; i < transport::kMessageHandlerThreadCount; ++i) {
        while (waiting_verify_block_queue_[i].size() > 0) {
            WaitingBlockItemPtr waiting_ptr;
            if (waiting_verify_block_queue_[i].pop(&waiting_ptr)) {
                auto members = elect::ElectManager::Instance()->GetNetworkMembersWithHeight(
                    waiting_ptr->block_ptr->electblock_height(),
                    waiting_ptr->block_ptr->network_id());
                if (members == nullptr) {
                    waiting_block_set_.insert(waiting_ptr);
                    continue;
                }

                if (VerifyAggSignWithMembers(members, *waiting_ptr->block_ptr)) {
                    HandleVerifiedBlock(
                        common::kInvalidUint32,
                        waiting_ptr->type,
                        *waiting_ptr->block_ptr,
                        waiting_ptr->block_ptr);
                }
            }
        }
    }

    verify_block_tick_.CutOff(
        kBlockToDbPeriod,
        std::bind(&BftManager::VerifyWaitingBlock, this));
}
// 
// void BftManager::CheckCommitBackupRecall() {
//     std::unordered_map<std::string, BftInterfacePtr> bft_hash_map;
//     {
//         std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
//         bft_hash_map = bft_hash_map_;
//     }
// 
//     for (auto iter = bft_hash_map.begin(); iter != bft_hash_map.end(); ++iter) {
//         iter->second->CheckCommitRecallBackup();
//     }
// 
//     leader_resend_tick_.CutOff(
//         300000,
//         std::bind(&BftManager::CheckCommitBackupRecall, this));
// }

}  // namespace bft

}  // namespace tenon
