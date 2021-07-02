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
}

BftManager::~BftManager() {}

BftManager* BftManager::Instance() {
    static BftManager ins;
    return &ins;
}

uint32_t BftManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    return elect::ElectManager::Instance()->GetMemberIndex(network_id, node_id);
}

void BftManager::HandleMessage(transport::protobuf::Header& header) {
    assert(header.type() == common::kBftMessage);
    bft::protobuf::BftMessage bft_msg;
    if (!bft_msg.ParseFromString(header.data())) {
        BFT_ERROR("protobuf::BftMessage ParseFromString failed!");
        return;
    }

    if (header.version() == 14 || header.version() == 15) {
        std::cout << "receive broadcast message: " << bft_msg.bft_step() << std::endl;
    }
    if (!bft_msg.has_bft_step()) {
        BFT_ERROR("bft_msg.has_status() failed!");
        return;
    }

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
        break;
    default:
        break;
    }

    BftInterfacePtr bft_ptr = nullptr;
    if (bft_msg.bft_step() == kBftPrepare && !bft_msg.leader()) {
        bft_ptr = std::make_shared<TxBft>();
        bft_ptr->set_gid(bft_msg.gid());
        bft_ptr->set_network_id(bft_msg.net_id());
        bft_ptr->set_randm_num(bft_msg.rand());
        bft_ptr->set_pool_index(bft_msg.pool_index());
        bft_ptr->set_status(kBftPrepare);
        bft_ptr->set_member_count(
            elect::ElectManager::Instance()->GetMemberCount(bft_msg.net_id()));
        if (!bft_ptr->CheckLeaderPrepare(bft_msg)) {
            BFT_ERROR("BackupPrepare leader invalid", bft_ptr, header);
            return;
        }

        AddBft(bft_ptr);
    } else {
        bft_ptr = GetBft(bft_msg.gid());
        if (bft_ptr == nullptr) {
            BFT_ERROR("get bft failed[%s]!", common::Encode::HexEncode(bft_msg.gid()).c_str());
            return;
        }
    }

    if (!bft_ptr) {
        assert(bft_ptr);
        return;
    }

    BFT_ERROR("HandleMessage %s, step: %d", common::Encode::HexEncode(bft_ptr->gid()).c_str(), bft_msg.bft_step());
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

    common::Bitmap leader_agg_bitmap(data);
    std::vector<security::PublicKey> pubkeys;
    uint32_t bit_size = leader_agg_bitmap.data().size() * 64;
    for (uint32_t i = 0; i < bit_size; ++i) {
        if (!leader_agg_bitmap.Valid(i)) {
            continue;
        }

        auto mem_ptr = elect::ElectManager::Instance()->GetMember(block.network_id(), i);
        pubkeys.push_back(mem_ptr->pubkey);
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
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        BFT_ERROR("root congress don't handle this message.");
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

    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }

    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == elect::kInvalidMemberIndex) {
        BFT_ERROR("HandleToAccountTxBlock failed mem index invalid: %u", mem_index);
        return;
    }

    security::Signature sign;
    if (VerifyBlockSignature(mem_index, bft_msg, tx_bft.to_tx().block(), sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return;
    }

    if (!AggSignValid(tx_bft.to_tx().block())) {
        BFT_ERROR("ts block agg sign verify failed!");
        return;
    }

    if (tx_list.size() == 1 && IsRootSingleBlockTx(tx_list[0].type())) {
        BFT_ERROR("IsRootSingleBlockTx(tx_list[0].type()): %d", tx_list[0].type());
        db::DbWriteBach db_batch;
        auto block_ptr = std::make_shared<bft::protobuf::Block>(tx_bft.to_tx().block());
        if (block::BlockManager::Instance()->AddNewBlock(
                block_ptr,
                db_batch) != block::kBlockSuccess) {
            BFT_ERROR("leader add block to db failed!");
            return;
        }

        auto st = db::Db::Instance()->Put(db_batch);
        if (!st.ok()) {
            exit(0);
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

    int32_t pool_mod_index = GetLeaderPoolIndex();
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

void BftManager::HandleToAccountTxBlock(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == elect::kInvalidMemberIndex) {
        BFT_ERROR("HandleToAccountTxBlock failed mem index invalid: %u", mem_index);
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
    security::Signature sign;
    if (VerifyBlockSignature(
            mem_index,
            bft_msg,
            tx_bft.mutable_to_tx()->block(),
            sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return;
    }


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
        LeaderBroadcastToAcc(std::make_shared<bft::protobuf::Block>(src_block));
    }

    int32_t pool_mod_index = GetLeaderPoolIndex();
    if (pool_mod_index >= 0) {
        StartBft("", pool_mod_index);
    }
}

int BftManager::InitBft(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    uint32_t network_id = 0;
    if (!DispatchPool::Instance()->InitCheckTxValid(bft_msg)) {
        DHT_ERROR("invalid bft request, gid cover or new addr cover![%s], type:[%d]",
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

    int32_t pool_mod_index = GetLeaderPoolIndex();
    if (pool_mod_index < 0) {
        return kBftSuccess;
    }

    res = StartBft(bft_msg.gid(), pool_mod_index);
    if (res != kBftSuccess) {
        if (res != kBftNoNewTxs) {
            BFT_WARN("start [%s][%u][%llu] failed![%d]",
                bft_msg.gid().c_str(),
                bft_msg.net_id(),
                bft_msg.rand(),
                res);
        }

        return res;
    }

    return kBftSuccess;
}

int BftManager::StartBft(const std::string& gid, int32_t pool_mod_index) {
    BftInterfacePtr bft_ptr = std::make_shared<TxBft>();
    bft_ptr->set_gid(common::GlobalInfo::Instance()->gid());
    bft_ptr->set_network_id(common::GlobalInfo::Instance()->network_id());
    bft_ptr->set_randm_num(vss::VssManager::Instance()->EpochRandom());
    bft_ptr->set_member_count(elect::ElectManager::Instance()->GetMemberCount(
        common::GlobalInfo::Instance()->network_id()));
    int leader_pre = LeaderPrepare(bft_ptr, pool_mod_index);
    if (leader_pre != kBftSuccess) {
        return leader_pre;
    }

    int res = AddBft(bft_ptr);
    if (res != kBftSuccess) {
        return res;
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

void BftManager::RemoveBft(const std::string& gid) {
    BftInterfacePtr bft_ptr{ nullptr };
    {
        std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
        auto iter = bft_hash_map_.find(gid);
        if (iter != bft_hash_map_.end()) {
            bft_ptr = iter->second;
            bft_hash_map_.erase(iter);
        }
    }

    if (bft_ptr) {
        DispatchPool::Instance()->BftOver(bft_ptr);
    }
}

int BftManager::LeaderPrepare(BftInterfacePtr& bft_ptr, int32_t pool_mod_idx) {
    std::string prepare_data;
    int res = bft_ptr->Prepare(true, pool_mod_idx, prepare_data);
    if (res != kBftSuccess) {
        return res;
    }

    uint32_t member_idx = GetMemberIndex(
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
        true,
        bft_ptr->secret(),
        common::GlobalInfo::Instance()->id());
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    if (dht_ptr == nullptr) {
        BFT_ERROR("this node has not joined consensus network[%u].", bft_ptr->network_id());
        return kBftError;
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
    if (!bft_ptr->BackupCheckLeaderValid(bft_msg)) {
        BFT_ERROR("leader check failed!");
        return kBftError;
    }

    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    auto& data = *(header.mutable_data());
    if (bft_ptr->Prepare(false, -1, data) != kBftSuccess) {
        BFT_ERROR("bft backup prepare failed!");
        std::string rand_num_str = std::to_string(rand() % (std::numeric_limits<int>::max)());
        BftProto::BackupCreatePrepare(
            header,
            bft_msg,
            local_node,
            rand_num_str,
            bft_ptr->secret(),
            false,
            msg);
        RemoveBft(bft_ptr->gid());
    } else {
        BftProto::BackupCreatePrepare(
            header,
            bft_msg,
            local_node,
            data,
            bft_ptr->secret(),
            true,
            msg);
    }

    if (!msg.has_data()) {
        BFT_ERROR("message set data failed!");
        return kBftError;
    }

    bft_ptr->set_status(kBftPreCommit);
    // send prepare to leader
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);
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
    if (!bft_ptr->LeaderCheckLeaderValid(bft_msg)) {
        BFT_ERROR("check leader vaild failed!");
        return kBftError;
    }

    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto& data = *(header.mutable_data());
    if (bft_ptr->PreCommit(true, data) != kBftSuccess) {
        BFT_ERROR("bft leader pre-commit failed!");
        return kBftError;
    }

    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == elect::kInvalidMemberIndex) {
        return kBftError;
    }

    security::Signature sign;
    if (VerifySignature(
            mem_index,
            bft_msg,
            BftProto::GetPrepareSignHash(bft_msg),
            sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return kBftError;
    }

    if (!bft_msg.has_secret()) {
        BFT_ERROR("backup prepare must has commit secret.");
        return kBftError;
    }
    security::CommitSecret backup_secret(bft_msg.secret());
    int res = bft_ptr->LeaderPrecommitOk(
            mem_index,
            bft_msg.agree(),
            backup_secret,
            security::Secp256k1::Instance()->ToAddressWithPublicKey(bft_msg.pubkey()));
    if (res == kBftAgree) {
        return LeaderCallPrecommit(bft_ptr);
    } else if (res == kBftOppose) {
        BFT_DEBUG("LeaderPrecommit RemoveBft kBftOppose");
        RemoveBft(bft_ptr->gid());
        BFT_DEBUG("LeaderPrecommit oppose", bft_ptr);
    } else {
        BFT_DEBUG("LeaderPrecommit waiting");
        // continue waiting, do nothing.
    }

    // broadcast pre-commit to backups
    return kBftSuccess;
}

int BftManager::LeaderCallPrecommit(BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign
    bft_ptr->init_precommit_timeout();
    uint32_t member_idx = GetMemberIndex(
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
            common::GlobalInfo::Instance()->id()) == kBftOppose) {
        BFT_ERROR("leader commit failed!");
        RemoveBft(bft_ptr->gid());
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
    if (!bft_ptr->BackupCheckLeaderValid(bft_msg)) {
        return kBftError;
    }

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
    auto& data = *(header.mutable_data());
    if (bft_ptr->PreCommit(false, data) != kBftSuccess) {
        BFT_ERROR("bft backup pre-commit failed!");
        std::string rand_num_str = std::to_string(rand() % (std::numeric_limits<int>::max)());
        BftProto::BackupCreatePreCommit(
            header,
            bft_msg,
            local_node,
            rand_num_str,
            agg_res,
            false,
            msg);
        RemoveBft(bft_ptr->gid());
    } else {
        BftProto::BackupCreatePreCommit(header, bft_msg, local_node, data, agg_res, true, msg);
    }

    if (!msg.has_data()) {
        return kBftError;
    }

    bft_ptr->set_status(kBftCommit);
    // send pre-commit to leader
    if (header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);
    }

#ifdef TENON_UNITTEST
    backup_precommit_msg_ = msg;
#endif
    std::string agg_res_str;
    agg_res.Serialize(agg_res_str);
    std::string agg_cha_str;
    agg_challenge.Serialize(agg_cha_str);
    std::string pri_key_str;
    security::Schnorr::Instance()->prikey()->Serialize(pri_key_str);
    std::string sec_key_str;
    bft_ptr->secret().Serialize(sec_key_str);
    std::string pub_key_str;
    security::Schnorr::Instance()->pubkey()->Serialize(pub_key_str);
    return kBftSuccess;
}

int BftManager::LeaderCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (!bft_ptr->LeaderCheckLeaderValid(bft_msg)) {
        BFT_ERROR("check leader error.");
        return kBftError;
    }

    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == elect::kInvalidMemberIndex) {
        BFT_ERROR("mem_index == elect::kInvalidMemberIndex.");
        return kBftError;
    }

    security::Signature sign;
    if (VerifySignature(
            mem_index,
            bft_msg,
            BftProto::GetPrecommitSignHash(bft_msg),
            sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return kBftError;
    }

    if (!bft_msg.has_response()) {
        BFT_ERROR("backup pre commit message must have response.");
        return kBftError;
    }

    security::Response agg_res(bft_msg.response());
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto& data = *(header.mutable_data());
    if (bft_ptr->Commit(true, data) != kBftSuccess) {
        BFT_ERROR("bft leader commit failed!");
        return kBftError;
    }

    int res = bft_ptr->LeaderCommitOk(
        mem_index,
        bft_msg.agree(),
        agg_res,
        security::Secp256k1::Instance()->ToAddressWithPublicKey(bft_msg.pubkey()));
    if (res == kBftAgree) {
        return LeaderCallCommit(bft_ptr);
    }  else if (res == kBftReChallenge) {
        return LeaderReChallenge(bft_ptr);
    } else if (res == kBftOppose) {
        BFT_DEBUG("LeaderCommit RemoveBft kBftOppose");
        RemoveBft(bft_ptr->gid());
        BFT_DEBUG("LeaderCommit oppose", bft_ptr);
    } else {
        // continue waiting, do nothing.
        BFT_DEBUG("LeaderCommit waiting", bft_ptr);
    }

    return kBftSuccess;
}

int BftManager::LeaderCallCommit(BftInterfacePtr& bft_ptr) {
    // check pre-commit multi sign and leader commit
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    BftProto::LeaderCreateCommit(local_node, bft_ptr, msg);
    if (!msg.has_data()) {
        BFT_ERROR("leader create commit message failed!");
        return kBftError;
    }

    auto tenon_block = bft_ptr->prpare_block();
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
        db::DbWriteBach db_batch;
        RootCommitAddNewAccount(*tenon_block, db_batch);
        auto st = db::Db::Instance()->Put(db_batch);
        if (!st.ok()) {
            exit(0);
        }
    }

    db::DbWriteBach db_batch;
    if (block::BlockManager::Instance()->AddNewBlock(
            tenon_block,
            db_batch) != block::kBlockSuccess) {
        BFT_ERROR("leader add block to db failed!");
        return kBftError;
    }

    auto st = db::Db::Instance()->Put(db_batch);
    if (!st.ok()) {
        exit(0);
    }

    bft_ptr->set_status(kBftCommited);
    network::Route::Instance()->Send(msg);
    LeaderBroadcastToAcc(bft_ptr->prpare_block());
    RemoveBft(bft_ptr->gid());
#ifdef TENON_UNITTEST
    leader_commit_msg_ = msg;
#endif
    BFT_DEBUG("LeaderCommit");
    return kBftSuccess;
}

int BftManager::LeaderReChallenge(BftInterfacePtr& bft_ptr) {
    transport::protobuf::Header msg;
    bft_ptr->init_precommit_timeout();
    uint32_t member_idx = GetMemberIndex(
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
            common::GlobalInfo::Instance()->id()) == kBftOppose) {
        BFT_ERROR("leader commit failed!");
        RemoveBft(bft_ptr->gid());
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
    if (block::BlockManager::Instance()->AddNewBlock(
            genesis_block,
            db_batch) != block::kBlockSuccess) {
        BFT_ERROR("leader add block to db failed!");
        return kBftError;
    }

    auto st = db::Db::Instance()->Put(db_batch);
    if (!st.ok()) {
        std::cout << "write db faled!" << std::endl;
        exit(0);
    }

    return kBftSuccess;
}

int BftManager::BackupCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (!bft_ptr->BackupCheckLeaderValid(bft_msg)) {
        return kBftError;
    }

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
    auto& data = *(header.mutable_data());
    if (bft_ptr->Commit(false, data) != kBftSuccess) {
        BFT_ERROR("bft backup commit failed!");
    }

    if (!bft_ptr->prpare_block()) {
        BFT_ERROR("bft_ptr->prpare_block failed!");
        exit(1);
    }

    auto tenon_block = bft_ptr->prpare_block();
    tenon_block->set_agg_sign_challenge(bft_msg.agg_sign_challenge());
    tenon_block->set_agg_sign_response(bft_msg.agg_sign_response());
    tenon_block->set_pool_index(bft_ptr->pool_index());
    for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
        tenon_block->add_bitmap(bft_msg.bitmap(i));
    }

    assert(tenon_block->bitmap_size() > 0);
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        db::DbWriteBach db_batch;
        RootCommitAddNewAccount(*tenon_block, db_batch);
        auto st = db::Db::Instance()->Put(db_batch);
        if (!st.ok()) {
            exit(0);
        }
    }

    db::DbWriteBach db_batch;
    if (block::BlockManager::Instance()->AddNewBlock(
            bft_ptr->prpare_block(),
            db_batch) != block::kBlockSuccess) {
        BFT_ERROR("backup add block to db failed!");
        return kBftError;
    }

    auto st = db::Db::Instance()->Put(db_batch);
    if (!st.ok()) {
        BFT_ERROR("batch put data failed[%s]", st.ToString().c_str());
        exit(1);
    }

    bft_ptr->set_status(kBftCommited);
    BFT_DEBUG("BackupCommit");
    RemoveBft(bft_ptr->gid());
    // start new bft
    return kBftSuccess;
}

void BftManager::LeaderBroadcastToAcc(const std::shared_ptr<bft::protobuf::Block>& block_ptr) {
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    if (!dht_ptr) {
        assert(false);
        return;
    }

    auto local_node = dht_ptr->local_node();
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (block_ptr->tx_list_size() == 1 &&
                (block_ptr->tx_list(0).type() == common::kConsensusFinalStatistic ||
                block_ptr->tx_list(0).type() == common::kConsensusStatistic)) {
            return;
        }

        transport::protobuf::Header msg;
        BftProto::CreateLeaderBroadcastToAccount(
            local_node,
            network::kNodeNetworkId,
            common::kBftMessage,
            block_ptr,
            msg);
        if (msg.has_data()) {
            msg.set_version(block_ptr->tx_list(0).type());
            network::Route::Instance()->Send(msg);
            network::Route::Instance()->SendToLocal(msg);
            BFT_ERROR("IsRootSingleBlockTx broadcast type: %d", block_ptr->tx_list(0).type());
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
            block_ptr,
            msg);
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
#ifdef TENON_UNITTEST
        to_leader_broadcast_msg_ = msg;
#endif
    }
}

void BftManager::CheckTimeout() {
    std::vector<BftInterfacePtr> timeout_vec;
    {
        std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
        for (auto iter = bft_hash_map_.begin(); iter != bft_hash_map_.end();) {
            int timeout_res = iter->second->CheckTimeout();
            printf("DDDDDDDDDDDD kTimeoutCallPrecommit.[%d]\n", timeout_res);
            BFT_DEBUG("DDDDDDDDDDDD kTimeoutCallPrecommit.[%d]", timeout_res);
            switch (timeout_res) {
                case kTimeout: {
                    timeout_vec.push_back(iter->second);
                    bft_hash_map_.erase(iter++);
                    break;
                }
                case kTimeoutCallPrecommit: {
                    printf("DDDDDDDDDDDD kTimeoutCallPrecommit.\n");
                    BFT_DEBUG("DDDDDDDDDDDD kTimeoutCallPrecommit.");
                    LeaderCallPrecommit(iter->second);
                    break;
                }
                case kTimeoutCallReChallenge: {
                    LeaderReChallenge(iter->second);
                    break;
                }
                case kTimeoutNormal:
                case kTimeoutWaitingBackup:
                    break;
                default:
                    break;
            }
            
            if (timeout_res != kTimeout) {
                ++iter;
            }
        }
    }

    for (uint32_t i = 0; i < timeout_vec.size(); ++i) {
        timeout_vec[i]->set_status(kBftStepTimeout);
        DispatchPool::Instance()->BftOver(timeout_vec[i]);
        BFT_ERROR("Timeout %s,", common::Encode::HexEncode(timeout_vec[i]->gid()).c_str());
    }

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
        uint32_t mem_index,
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& sha128,
        security::Signature& sign) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    auto mem_ptr = elect::ElectManager::Instance()->GetMember(bft_msg.net_id(), mem_index);
    if (!mem_ptr) {
        return kBftError;
    }

    if (!security::Schnorr::Instance()->Verify(sha128, sign, mem_ptr->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftManager::VerifyBlockSignature(
        uint32_t mem_index,
        const bft::protobuf::BftMessage& bft_msg,
        const bft::protobuf::Block& tx_block,
        security::Signature& sign) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    auto mem_ptr = elect::ElectManager::Instance()->GetMember(bft_msg.net_id(), mem_index);
    if (!mem_ptr) {
        return kBftError;
    }

    auto block_hash = GetBlockHash(tx_block);
    if (block_hash != tx_block.hash()) {
        return kBftError;
    }

    if (!security::Schnorr::Instance()->Verify(block_hash, sign, mem_ptr->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }

    return kBftSuccess;
}

int BftManager::VerifyLeaderSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    auto sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    auto mem_ptr = elect::ElectManager::Instance()->GetMember(
        bft_msg.net_id(),
        bft_ptr->leader_index());
    if (!mem_ptr) {
        return kBftError;
    }


    std::string hash_to_sign = bft_ptr->prepare_hash();
    if (bft_msg.bft_step() == kBftCommit) {
        std::string msg_hash_src = bft_ptr->prepare_hash();
        for (int32_t i = 0; i < bft_msg.bitmap_size(); ++i) {
            msg_hash_src += std::to_string(bft_msg.bitmap(i));
        }

        hash_to_sign = common::Hash::Hash256(msg_hash_src);
    }

    std::string pubkey_str;
    mem_ptr->pubkey.Serialize(pubkey_str);
    if (!security::Schnorr::Instance()->Verify(
            hash_to_sign,
            sign,
            mem_ptr->pubkey)) {
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

}  // namespace bft

}  // namespace tenon
