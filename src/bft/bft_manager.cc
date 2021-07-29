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
}

BftManager::~BftManager() {}

BftManager* BftManager::Instance() {
    static BftManager ins;
    return &ins;
}

uint32_t BftManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    return elect::ElectManager::Instance()->GetMemberIndex(network_id, node_id);
}

void BftManager::HandleMessage(transport::TransportMessagePtr& header_ptr) {
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

    BFT_ERROR("msg id: %lu, leader: %d, HandleMessage %s, step: %d, from:%s:%d, bft_msg.bft_step(): %d",
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
//             BFT_DEBUG("leader get bft gid failed[%s]",
//                 common::Encode::HexEncode(bft_msg.gid()).c_str());
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
        transport::TransportMessagePtr& header_ptr) {
    if (!bft_msg.leader()) {
        if (bft_ptr->ThisNodeIsLeader(bft_msg)) {
//             BFT_DEBUG("this node is leader not handle backup message.");
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
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
//     if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
//         CreateRootGenisisBlock();
//     } else {
//         CreateConsenseGenisisBlock();
//     }

    return kBftSuccess;
}

bool BftManager::AggSignValid(const bft::protobuf::Block& block) {
    if (!block.has_agg_sign_challenge() ||
            !block.has_agg_sign_response() ||
            block.bitmap_size() <= 0) {
        BFT_ERROR("commit must have agg sign. block.has_agg_sign(): %d,"
            "block.has_agg_sign_response(): %d, block.bitmap_size(): %u",
            block.has_agg_sign_challenge(), block.has_agg_sign_response(), block.bitmap_size());
        return false;
    }

    auto sign = security::Signature(block.agg_sign_challenge(), block.agg_sign_response());
    std::vector<uint64_t> data;
    for (int32_t i = 0; i < block.bitmap_size(); ++i) {
        data.push_back(block.bitmap(i));
    }

    auto members = elect::ElectManager::Instance()->GetNetworkMembersWithHeight(
        block.electblock_height(),
        block.network_id());
    if (members == nullptr) {
        BFT_ERROR("get members failed height: %lu", block.electblock_height());
        assert(false);
        return false;
    }

    common::Bitmap leader_agg_bitmap(data);
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = leader_agg_bitmap.data().size() * 64;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!leader_agg_bitmap.Valid(i)) {
            continue;
        }

        if (members->size() <= i) {
            return false;
        }

        pubkeys.push_back((*members)[i]->pubkey);
    }

    auto agg_pubkey = security::MultiSign::AggregatePubKeys(pubkeys);
    auto block_hash = GetBlockHash(block);
    assert(agg_pubkey != nullptr);
    if (!security::MultiSign::Instance()->MultiSigVerify(
            block_hash,
            sign,
            *agg_pubkey)) {
        return false;
    }

    return true;
}

void BftManager::HandleRootTxBlock(
        transport::protobuf::Header& header,
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

//     if (block::BlockManager::Instance()->BlockExists(tx_bft.to_tx().block().hash())) {
//         return;
//     }

    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        BFT_ERROR("HandleToAccountTxBlock failed mem index invalid: %u", bft_msg.member_index());
        return;
    }

//     security::Signature sign;
//     if (VerifyBlockSignature(
//             bft_msg.member_index(),
//             bft_msg,
//             tx_bft.to_tx().block(),
//             sign) != kBftSuccess) {
//         BFT_ERROR("verify signature error!");
//         return;
//     }

    if (!AggSignValid(tx_bft.to_tx().block())) {
        BFT_ERROR("root block agg sign verify failed! height: %lu, type: %d",
            tx_bft.to_tx().block().height(),
            tx_bft.to_tx().block().tx_list(0).type());
        return;
    }

    for (int32_t i = 0; i < tx_list.size(); ++i) {
        DispatchPool::Instance()->RemoveTx(
            tx_bft.to_tx().block().pool_index(),
            tx_list[i].to_add(),
            tx_list[i].type(),
            tx_list[i].call_contract_step(),
            tx_list[i].gid());
    }

    if (tx_list.size() == 1 && IsRootSingleBlockTx(tx_list[0].type())) {
        auto block_ptr = std::make_shared<bft::protobuf::Block>(tx_bft.to_tx().block());
        auto queue_item_ptr = std::make_shared<BlockToDbItem>(block_ptr);
        if (block::AccountManager::Instance()->AddBlockItemToCache(
                queue_item_ptr->block_ptr,
                queue_item_ptr->db_batch) != block::kBlockSuccess) {
            BFT_ERROR("leader add block to db failed!");
        }

        block_queue_[header.thread_idx()].push(queue_item_ptr);
        return;
    }

    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].status() != 0) {
            continue;
        }

        db::DbWriteBach db_batch;
        if (block::AccountManager::Instance()->AddNewAccount(
                tx_list[i],
                tx_bft.to_tx().block().height(),
                tx_bft.to_tx().block().hash(),
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
        transport::protobuf::Header& header,
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

//     if (block::BlockManager::Instance()->BlockExists(tx_bft.to_tx().block().hash())) {
//         return;
//     }

    auto src_block = tx_bft.to_tx().block();
//     security::Signature sign;
//     if (VerifyBlockSignature(
//             bft_msg.member_index(),
//             bft_msg,
//             tx_bft.mutable_to_tx()->block(),
//             sign) != kBftSuccess) {
//         BFT_ERROR("verify signature error!");
//         return;
//     }

    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    if (!AggSignValid(tx_bft.to_tx().block())) {
        BFT_ERROR("sync block agg sign verify failed!");
        return;
    }

//     BFT_ERROR("HandleSyncBlock: %s", common::Encode::HexEncode(tx_bft.to_tx().block().hash()).c_str());
    auto block_ptr = std::make_shared<bft::protobuf::Block>(tx_bft.to_tx().block());
    auto queue_item_ptr = std::make_shared<BlockToDbItem>(block_ptr);
    if (block::AccountManager::Instance()->AddBlockItemToCache(
            queue_item_ptr->block_ptr,
            queue_item_ptr->db_batch) != block::kBlockSuccess) {
        BFT_ERROR("leader add block to db failed!");
        return;
    }

    block_queue_[header.thread_idx()].push(queue_item_ptr);
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        DispatchPool::Instance()->RemoveTx(
            block_ptr->pool_index(),
            tx_list[i].to_add(),
            tx_list[i].type(),
            tx_list[i].call_contract_step(),
            tx_list[i].gid());
    }
}

void BftManager::HandleToAccountTxBlock(
        transport::protobuf::Header& header,
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
//     security::Signature sign;
//     if (VerifyBlockSignature(
//             bft_msg.member_index(),
//             bft_msg,
//             tx_bft.mutable_to_tx()->block(),
//             sign) != kBftSuccess) {
//         BFT_ERROR("verify signature error!");
//         return;
//     }

    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    if (!AggSignValid(tx_bft.to_tx().block())) {
        BFT_ERROR("ts block agg sign verify failed!");
        return;
    }

    bool just_broadcast = false;
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].type() == common::kConsensusFinalStatistic) {
            bft::protobuf::TxInfo tx_info;
            if (elect::ElectManager::Instance()->CreateElectTransaction(
                    tx_list[i].network_id(),
                    tx_bft.to_tx().block().height(),
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

        tx_list[i].set_to_add(true);
        if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
            auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(tx_list[i].to());
            if (account_ptr != nullptr) {
                // root just create account address and assignment consensus network id
                just_broadcast = true;
                BFT_ERROR("account address exists error and broadcast it from [%s] to [%s]!",
                    common::Encode::HexEncode(tx_list[i].from()).c_str(),
                    common::Encode::HexEncode(tx_list[i].to()).c_str());
                continue;
            }

            if (tx_list[i].amount() <= 0 &&
                    tx_list[i].type() != common::kConsensusCreateContract) {
                BFT_ERROR("transfer amount error!");
                continue;
            }
        }

        if (DispatchPool::Instance()->Dispatch(tx_list[i]) != kBftSuccess) {
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

int BftManager::InitBft(
        transport::protobuf::Header& header,
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
        return leader_pre;
    }

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
    int res = bft_ptr->Prepare(true, pool_mod_idx, &prepare_data);
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

    bft_ptr->LeaderPrecommitOk(
        member_idx,
        bft_ptr->gid(),
        0,
        true,
        bft_ptr->secret(),
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
    transport::protobuf::Header msg;
    BftProto::LeaderCreatePrepare(
        local_node,
        prepare_data,
        bft_ptr,
        leader_sig,
        msg);

    network::Route::Instance()->Send(msg);
    bft_ptr->init_prepare_timeout();

    // (TODO): just for test
#ifdef TENON_UNITTEST
    leader_prepare_msg_ = msg;
#endif
    return kBftSuccess;
}

int BftManager::BackupPrepare(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    if (!bft_ptr->CheckLeaderPrepare(bft_msg)) {
        std::string res_data = std::to_string(kBftInvalidPackage) + ",-1";
        BftProto::BackupCreatePrepare(
            header,
            bft_msg,
            local_node,
            res_data,
            bft_ptr,
            false,
            msg);
        RemoveBft(bft_ptr->gid(), false);
        BFT_ERROR("0 bft backup prepare failed! not agree bft gid: %s",
            common::Encode::HexEncode(bft_ptr->gid()).c_str());
    } else {
        auto data = header.mutable_data();
        int prepare_res = bft_ptr->Prepare(false, -1, data);
        if (prepare_res != kBftSuccess) {
            std::string res_data = std::to_string(prepare_res) + "," + *data;
            BftProto::BackupCreatePrepare(
                header,
                bft_msg,
                local_node,
                res_data,
                bft_ptr,
                false,
                msg);
            RemoveBft(bft_ptr->gid(), false);
            BFT_ERROR("1 bft backup prepare failed! not agree bft gid: %s",
                common::Encode::HexEncode(bft_ptr->gid()).c_str());
        } else {
            BftProto::BackupCreatePrepare(
                header,
                bft_msg,
                local_node,
                *data,
                bft_ptr,
                true,
                msg);
            BFT_ERROR("bft backup prepare success! agree bft gid: %s, from: %s:%d",
                common::Encode::HexEncode(bft_ptr->gid()).c_str(),
                bft_msg.node_ip().c_str(), bft_msg.node_port());
        }
    }

    if (!msg.has_data()) {
        BFT_ERROR("message set data failed!");
        return kBftError;
    }

    bft_ptr->set_status(kBftPreCommit);
    // send prepare to leader
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            bft_msg.node_ip(), bft_msg.node_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);
    }

#ifdef TENON_UNITTEST
    backup_prepare_msg_ = msg;
#endif
    return kBftSuccess;
}

int BftManager::LeaderPrecommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
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

    const auto& member_ptr = (*bft_ptr->members_ptr())[bft_msg.member_index()];
    auto backup_prepare_hash = BftProto::GetPrepareSignHash(bft_msg);
    std::string dec_data;
    if (member_ptr->backup_ecdh_key.empty()) {
        BFT_ERROR("get backup ecdh key failed! network id: %d, node id: %s, mem index: %d",
            common::GlobalInfo::Instance()->network_id(), common::Encode::HexEncode(member_ptr->id).c_str(), bft_msg.member_index());
//         assert(false);
        return kBftError;
    }

    if (security::Crypto::Instance()->GetDecryptData(
            member_ptr->backup_ecdh_key,
            bft_msg.backup_enc_data(),
            &dec_data) != security::kSecuritySuccess) {
        BFT_ERROR("verify encrypt prepare hash error!");
        return kBftError;
    }

//     time2 = common::TimeUtils::TimestampUs();
    if (memcmp(backup_prepare_hash.c_str(), dec_data.c_str(), backup_prepare_hash.size()) != 0) {
        BFT_ERROR("verify encrypt prepare hash error!");
        return kBftError;
    }

    if (!bft_msg.has_secret()) {
        BFT_ERROR("backup prepare must has commit secret.");
        return kBftError;
    }
    
    security::CommitSecret backup_secret(bft_msg.secret());
    int res = bft_ptr->LeaderPrecommitOk(
        bft_msg.member_index(),
        bft_ptr->gid(),
        header.id(),
        bft_msg.agree(),
        backup_secret,
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
//         BFT_DEBUG("LeaderPrecommit RemoveBft kBftOppose pool_index: %u, bft: %s", bft_ptr->pool_index(), common::Encode::HexEncode(member_ptr->id).c_str());
        RemoveBft(bft_ptr->gid(), false);
//         time4 = common::TimeUtils::TimestampUs();
    } else {
//         BFT_DEBUG("LeaderPrecommit %d waiting pool_index: %u, bft: %s", bft_msg.agree(), bft_ptr->pool_index(), common::Encode::HexEncode(member_ptr->id).c_str());
//         time4 = common::TimeUtils::TimestampUs();
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

int BftManager::LeaderCallPrecommit(BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign
    bft_ptr->init_precommit_timeout();
    security::Response sec_res(
            bft_ptr->secret(),
            bft_ptr->challenge(),
            *(security::Schnorr::Instance()->prikey()));
    if (bft_ptr->LeaderCommitOk(
            elect::ElectManager::Instance()->local_node_member_index(),
            true,
            sec_res,
            common::GlobalInfo::Instance()->id()) != kBftWaitingBackup) {
        BFT_ERROR("leader commit failed!");
        RemoveBft(bft_ptr->gid(), false);
        return kBftError;
    }

    transport::protobuf::Header msg;
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    BftProto::LeaderCreatePreCommit(local_node, bft_ptr, msg);
    network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
    leader_precommit_msg_ = msg;
#endif
    return kBftSuccess;
}

int BftManager::BackupPrecommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (VerifyLeaderSignature(bft_ptr, bft_msg) != kBftSuccess) {
        BFT_ERROR("check leader signature error!");
        return kBftError;
    }

    if (!bft_msg.has_challenge()) {
        BFT_ERROR("leader pre commit message must has challenge.");
        return false;
    }

    security::Challenge agg_challenge(bft_msg.challenge());
    security::Response agg_res(
            bft_ptr->secret(),
            agg_challenge,
            *(security::Schnorr::Instance()->prikey()));
    // check prepare multi sign
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    std::string precommit_data;
    if (bft_ptr->PreCommit(false, precommit_data) != kBftSuccess) {
//         BFT_DEBUG("bft backup pre-commit failed! not agree bft gid: %s",
//             common::Encode::HexEncode(bft_ptr->gid()).c_str());
        std::string rand_num_str = std::to_string(rand() % (std::numeric_limits<int>::max)());
        if (bft_ptr->leader_mem_ptr()->leader_ecdh_key.empty()) {
            BFT_ERROR("get leader ecdh key failed [%s]", common::Encode::HexDecode(bft_ptr->leader_mem_ptr()->id).c_str());
//             assert(false);
            return kBftError;
        }

        BftProto::BackupCreatePreCommit(
            header,
            bft_msg,
            local_node,
            rand_num_str,
            bft_ptr->leader_mem_ptr()->leader_ecdh_key,
            agg_res,
            false,
            msg);
        RemoveBft(bft_ptr->gid(), false);
    } else {
//         BFT_DEBUG("bft backup pre-commit from: %d success! agree bft gid: %s, from: %s:%d",
//             header.from_port(), common::Encode::HexEncode(bft_ptr->gid()).c_str(),
//             bft_msg.node_ip().c_str(), bft_msg.node_port());
        if (bft_ptr->leader_mem_ptr()->leader_ecdh_key.empty()) {
            BFT_ERROR("get leader ecdh key failed [%s]", common::Encode::HexDecode(bft_ptr->leader_mem_ptr()->id).c_str());
//             assert(false);
            return kBftError;
        }

        BftProto::BackupCreatePreCommit(
            header,
            bft_msg,
            local_node,
            precommit_data,
            bft_ptr->leader_mem_ptr()->leader_ecdh_key,
            agg_res,
            true,
            msg);
    }

    if (!msg.has_data()) {
        return kBftError;
    }

    bft_ptr->set_status(kBftCommit);
    // send pre-commit to leader
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            bft_msg.node_ip(), bft_msg.node_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);
    }

#ifdef TENON_UNITTEST
    backup_precommit_msg_ = msg;
#endif
    return kBftSuccess;
}

int BftManager::LeaderCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
//     uint64_t time1 = common::TimeUtils::TimestampUs();
//     uint64_t time2;
//     uint64_t time3;
//     uint64_t time4;
//     uint64_t time5;

    if (!bft_ptr->LeaderCheckLeaderValid(bft_msg)) {
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

    auto backup_precommit_hash = BftProto::GetPrecommitSignHash(bft_msg);
    if ((*bft_ptr->members_ptr())[bft_msg.member_index()]->backup_ecdh_key.empty()) {
        BFT_ERROR("get backup ecdh key failed! network id: %d, node id: %s, mem index: %d",
            common::GlobalInfo::Instance()->network_id(),
            common::Encode::HexEncode((*bft_ptr->members_ptr())[bft_msg.member_index()]->id).c_str(),
            bft_msg.member_index());
        //         assert(false);
        return kBftError;
    }
    std::string dec_data;
    if (security::Crypto::Instance()->GetDecryptData(
            (*bft_ptr->members_ptr())[bft_msg.member_index()]->backup_ecdh_key,
            bft_msg.backup_enc_data(),
            &dec_data) != security::kSecuritySuccess) {
        BFT_ERROR("verify encrypt prepare hash error!");
        return kBftError;
    }
//     time2 = common::TimeUtils::TimestampUs();
    if (memcmp(backup_precommit_hash.c_str(), dec_data.c_str(), backup_precommit_hash.size()) != 0) {
        BFT_ERROR("verify encrypt prepare hash error!");
        return kBftError;
    }

    if (!bft_msg.has_response()) {
        BFT_ERROR("backup pre commit message must have response.");
        return kBftError;
    }

    security::Response agg_res(bft_msg.response());
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    if (bft_msg.member_index() == elect::kInvalidMemberIndex) {
        return kBftError;
    }

    if (bft_ptr->members_ptr()->size() <= bft_msg.member_index()) {
        return kBftError;
    }

    const auto& member_ptr = (*bft_ptr->members_ptr())[bft_msg.member_index()];
//     time3 = common::TimeUtils::TimestampUs();
    int res = bft_ptr->LeaderCommitOk(
        bft_msg.member_index(),
        bft_msg.agree(),
        agg_res,
        member_ptr->id);
//     time4 = common::TimeUtils::TimestampUs();
    if (res == kBftAgree) {
        LeaderCallCommit(header, bft_ptr);
//         time5 = common::TimeUtils::TimestampUs();
    }
    else if (res == kBftReChallenge) {
        LeaderReChallenge(bft_ptr);
//         time5 = common::TimeUtils::TimestampUs();
    }
    else if (res == kBftOppose) {
//         BFT_DEBUG("LeaderCommit RemoveBft kBftOppose pool_index: %u", bft_ptr->pool_index());
        RemoveBft(bft_ptr->gid(), false);
//         time5 = common::TimeUtils::TimestampUs();
    }

//     BFT_DEBUG("bft: %s, LeaderPrecommit use time: %lu, %lu, %lu, %lu", common::Encode::HexEncode(member_ptr->id).c_str(), time2 - time1, time3 - time2, time4 - time3, time5 - time4);
    return kBftSuccess;
}

int BftManager::LeaderCallCommit(transport::protobuf::Header& header, BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign and leader commit
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    BftProto::LeaderCreateCommit(local_node, bft_ptr, msg);
    if (!msg.has_data()) {
        BFT_ERROR("leader create commit message failed!");
        return kBftError;
    }

    auto& tenon_block = bft_ptr->prpare_block();
    std::string agg_sign_challenge_str;
    std::string agg_sign_response_str;
    bft_ptr->agg_sign()->Serialize(agg_sign_challenge_str, agg_sign_response_str);
    tenon_block->set_agg_sign_challenge(agg_sign_challenge_str);
    tenon_block->set_agg_sign_response(agg_sign_response_str);
    tenon_block->set_pool_index(bft_ptr->pool_index());
    const auto& bitmap_data = bft_ptr->precommit_bitmap().data();
    for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
        tenon_block->add_bitmap(bitmap_data[i]);
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
        BFT_ERROR("leader add block to db failed!");
        return kBftError;
    }

    block_queue_[header.thread_idx()].push(queue_item_ptr);
    bft_ptr->set_status(kBftCommited);
    network::Route::Instance()->Send(msg);
    LeaderBroadcastToAcc(bft_ptr, true);
    assert(bft_ptr->prpare_block()->bitmap_size() == tenon_block->bitmap_size());
    RemoveBft(bft_ptr->gid(), true);
#ifdef TENON_UNITTEST
    leader_commit_msg_ = msg;
#endif
//     BFT_DEBUG("LeaderCommit success waiting pool_index: %u, bft gid: %s",
//         bft_ptr->pool_index(), common::Encode::HexEncode(bft_ptr->gid()).c_str());
    return kBftSuccess;
}

int BftManager::LeaderReChallenge(BftInterfacePtr& bft_ptr) {
    transport::protobuf::Header msg;
    bft_ptr->init_precommit_timeout();
    uint32_t member_idx = bft_ptr->mem_manager_ptr()->GetMemberIndex(
        bft_ptr->network_id(),
        common::GlobalInfo::Instance()->id());
    if (member_idx == elect::kInvalidMemberIndex) {
        return kBftError;
    }

    security::Response sec_res(
        bft_ptr->secret(),
        bft_ptr->challenge(),
        *(security::Schnorr::Instance()->prikey()));
    if (bft_ptr->LeaderCommitOk(
            member_idx,
            true,
            sec_res,
            common::GlobalInfo::Instance()->id()) != kBftWaitingBackup) {
        BFT_ERROR("leader commit failed!");
        RemoveBft(bft_ptr->gid(), false);
        return kBftError;
    }

    std::string agg_res_str;
    sec_res.Serialize(agg_res_str);
    std::string agg_cha_str;
    bft_ptr->challenge().Serialize(agg_cha_str);
    std::string pri_key_str;
    security::Schnorr::Instance()->prikey()->Serialize(pri_key_str);
    std::string sec_key_str;
    bft_ptr->secret().Serialize(sec_key_str);
    std::string pub_key_str;
    security::Schnorr::Instance()->pubkey()->Serialize(pub_key_str);
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    BftProto::LeaderCreatePreCommit(local_node, bft_ptr, msg);
    network::Route::Instance()->Send(msg);
#ifdef TENON_UNITTEST
    leader_precommit_msg_ = msg;
#endif
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
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (VerifyLeaderSignature(bft_ptr, bft_msg) != kBftSuccess) {
        BFT_ERROR("check leader signature error!");
        return kBftError;
    }
    
    if (VerifyAggSignature(bft_ptr, bft_msg) != kBftSuccess) {
        BFT_ERROR("check bft agg signature error!");
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
    tenon_block->set_agg_sign_challenge(bft_msg.agg_sign_challenge());
    tenon_block->set_agg_sign_response(bft_msg.agg_sign_response());
    tenon_block->set_pool_index(bft_ptr->pool_index());
    for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
        tenon_block->add_bitmap(bft_msg.bitmap(i));
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
//     BFT_DEBUG("BackupCommit success waiting pool_index: %u, bft gid: %s",
//         bft_ptr->pool_index(), common::Encode::HexEncode(bft_ptr->gid()).c_str());
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
        case kTimeoutCallReChallenge: {
            iter->second->AddBftEpoch();
            LeaderReChallenge(iter->second);
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
        const bft::protobuf::BftMessage& bft_msg) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    auto sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    std::string hash_to_sign = bft_ptr->prepare_hash();
    if (bft_msg.bft_step() == kBftCommit) {
        std::string msg_hash_src = bft_ptr->prepare_hash();
        for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
            msg_hash_src += std::to_string(bft_msg.bitmap(i));
        }

        hash_to_sign = common::Hash::Hash256(msg_hash_src);
    }

    if (!security::Schnorr::Instance()->Verify(
            hash_to_sign,
            sign,
            bft_ptr->leader_mem_ptr()->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftManager::VerifyAggSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg) {
    if (bft_ptr->BackupCheckAggSign(bft_msg) != kBftSuccess) {
        BFT_ERROR("check agg sign failed!");
        return kBftError;
    }

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

}  // namespace bft

}  // namespace tenon
