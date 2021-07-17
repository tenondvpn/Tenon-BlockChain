#include "stdafx.h"
#include "block/block_manager.h"

#include "common/encode.h"
#include "common/time_utils.h"
#include "db/db.h"
#include "dht/dht_key.h"
#include "dht/base_dht.h"
#include "dht/dht_utils.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "network/network_utils.h"
#include "network/universal.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "statistics/statistics.h"
#include "block/block_utils.h"
#include "block/account_manager.h"
#include "block/proto/block.pb.h"
#include "block/proto/block_proto.h"
#include "bft/proto/bft_proto.h"
#include "election/proto/elect.pb.h"
#include "election/elect_manager.h"
#include "init/update_vpn_init.h"
#include "timeblock/time_block_manager.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const tenon::block::HeightCacheHeapItem& val) {
    return val.height;
}

}  // namespace common

}  // namespace tenon

namespace tenon {

namespace block {

bool operator<(HeightCacheHeapItem& lhs, HeightCacheHeapItem& rhs) {
    return lhs.cache_count < rhs.cache_count;
}

bool operator==(const HeightCacheHeapItem& lhs, const HeightCacheHeapItem& rhs) {
    return lhs.height == rhs.height;
}

static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;

static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kBftBroadcastStopTimes);
    broad_param->set_hop_limit(kBftHopLimit);
    broad_param->set_hop_to_layer(kBftHopToLayer);
    broad_param->set_neighbor_count(kBftNeighborCount);
}

static std::string CreateAdRewardRequest(
        const std::string& gid,
        const std::string& to,
        uint64_t amount,
        transport::protobuf::Header& msg) {
    auto uni_dht = std::dynamic_pointer_cast<network::Universal>(
            network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId));
    if (!uni_dht) {
        return "";
    }

    msg.set_src_dht_key(uni_dht->local_node()->dht_key());
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft_msg.set_node_id(common::GlobalInfo::Instance()->id());
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from(common::GlobalInfo::Instance()->id());
    new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
    new_tx->set_to(to);
    new_tx->set_amount(amount);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);

    auto hash128 = common::Hash::Hash128(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            sign)) {
        TRANSPORT_ERROR("leader pre commit signature failed!");
        return "";
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
    return gid;
}

BlockManager* BlockManager::Instance() {
    static BlockManager ins;
    return &ins;
}

BlockManager::BlockManager() {
}

BlockManager::~BlockManager() {}

int BlockManager::Init(common::Config& conf) {
    if (InitRootSingleBlocks() != kBlockSuccess) {
        return kBlockError;
    }

    network::Route::Instance()->RegisterMessage(
        common::kBlockMessage,
        std::bind(&BlockManager::HandleMessage, this, std::placeholders::_1));

    bool genesis = false;
    return kBlockSuccess;
}

int BlockManager::InitRootSingleBlocks() {
    if (InitRootElectBlocks() != kBlockSuccess) {
        return kBlockError;
    }
    
    if (InitRootTimeBlocks() != kBlockSuccess) {
        return kBlockError;
    }

    return kBlockSuccess;
}

int BlockManager::InitRootTimeBlocks() {
    auto account_info = AccountManager::Instance()->GetAcountInfo(
        common::kRootChainSingleBlockTxAddress);
    if (account_info == nullptr) {
        BLOCK_INFO("get root single block tx address failed![%s]",
            common::Encode::HexEncode(common::kRootChainSingleBlockTxAddress).c_str());
        return kBlockSuccess;
    }

    uint64_t latest_time_block_height = 0;
    uint64_t latest_time_block_tm = 0;
    uint64_t latest_time_block_vss_random = 0;
    if (account_info->GetLatestTimeBlock(
            &latest_time_block_height,
            &latest_time_block_tm,
            &latest_time_block_vss_random) != kBlockSuccess) {
        BLOCK_INFO("get root single block GetLatestTimeBlock failed![%s]",
            common::Encode::HexEncode(common::kRootChainSingleBlockTxAddress).c_str());
        return kBlockSuccess;
    }

    tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(
        latest_time_block_height,
        latest_time_block_tm,
        latest_time_block_vss_random);
    return kBlockSuccess;
}

int BlockManager::InitRootElectBlocks() {
    auto account_info = AccountManager::Instance()->GetAcountInfo(
        common::kRootChainSingleBlockTxAddress);
    if (account_info == nullptr) {
        BLOCK_INFO("this node not load elect blocks, no root address info.");
        return kBlockSuccess;
    }

    for (uint32_t i = network::kRootCongressNetworkId;
            i < network::kConsensusShardEndNetworkId; ++i) {
        uint64_t latest_elect_block_height = 0;
        std::string latest_elect_block_str;
        if (account_info->GetLatestElectBlock(
                i,
                &latest_elect_block_height,
                &latest_elect_block_str) != kBlockSuccess) {
            BLOCK_INFO("this node not load elect blocks, no latest elect block.");
            return kBlockSuccess;
        }

        elect::protobuf::ElectBlock elect_block;
        if (!elect_block.ParseFromString(latest_elect_block_str)) {
            BLOCK_ERROR("this node not load elect blocks, parse failed");
            return kBlockError;
        }

        elect::ElectManager::Instance()->ProcessNewElectBlock(
            latest_elect_block_height,
            elect_block,
            false);
        vss::VssManager::Instance()->OnElectBlock(
            elect_block.shard_network_id(),
            latest_elect_block_height);
    }
    
    return kBlockSuccess;
}

void BlockManager::HandleMessage(transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
    if (header.type() != common::kBlockMessage) {
        return;
    }

    protobuf::BlockMessage block_msg;
    if (!block_msg.ParseFromString(header.data())) {
        return;
    }

    if (block_msg.has_block_req()) {
        HandleGetBlockRequest(header, block_msg);
        return;
    }

    if (block_msg.has_height_req()) {
        HandleGetHeightRequest(header, block_msg);
        return;
    }

    if (block_msg.has_account_init_res()) {
        init::UpdateVpnInit::Instance()->UpdateAccountBlockInfo(header.data());
        return;
    }

    if (block_msg.has_account_init_req()) {
        HandleGetAccountInitRequest(header, block_msg);
        return;
    }

    if (block_msg.has_ad_reward_req()) {
        HandleAdRewardRequest(header, block_msg);
        return;
    }

    network::Route::Instance()->Send(header);
}

void BlockManager::HandleAdRewardRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
            block_msg.ad_reward_req().id());
    if (account_ptr == nullptr) {
        return;
    }

    if (block_msg.ad_reward_req().reward_key().size() != common::kAdRewardVersionStr.size()) {
        BLOCK_ERROR("error HandleAdRewardRequest coming, id: %s, key: %s, gid: %s",
            common::Encode::HexEncode(block_msg.ad_reward_req().id()).c_str(),
            common::Encode::HexEncode(block_msg.ad_reward_req().reward_key()).c_str(),
            common::Encode::HexEncode(block_msg.ad_reward_req().gid()).c_str());
        return;
    }

    if (block_msg.ad_reward_req().reward_key() < common::kAdRewardVersionStr) {
        BLOCK_ERROR("error HandleAdRewardRequest coming, id: %s, key: %s, gid: %s",
            common::Encode::HexEncode(block_msg.ad_reward_req().id()).c_str(),
            common::Encode::HexEncode(block_msg.ad_reward_req().reward_key()).c_str(),
            common::Encode::HexEncode(block_msg.ad_reward_req().gid()).c_str());
        return;
    }

    srand(time(NULL));
    uint32_t rand_count = rand() % 100;
    int64_t amount = 1;
    if (rand_count < 85) {
        amount = 1;
    } else if (rand_count < 90) {
        amount = rand() % 3 + 1;
    } else if (rand_count < 95) {
        amount = rand() % 4 + 2;
    } else {
        amount = rand() % 7 + 4;
    }

    amount = FixRewardWithHistory(block_msg.ad_reward_req().id(), amount);
    if (amount <= 0) {
        amount = rand() % (common::kTenonMiniTransportUnit / 10) + common::kTenonMiniTransportUnit / 100;
    } else if (amount == 1) {
        amount = rand() % (common::kTenonMiniTransportUnit / 2) + common::kTenonMiniTransportUnit / 10;
    } else {
        amount = rand() % common::kTenonMiniTransportUnit + (common::kTenonMiniTransportUnit / 2);
    }

    transport::protobuf::Header msg;
    std::string gid = CreateAdRewardRequest(
            block_msg.ad_reward_req().gid(),
            block_msg.ad_reward_req().id(),
            amount,
            msg);
    if (gid.empty()) {
        return;
    }

    network::Route::Instance()->Send(msg);
    network::Route::Instance()->SendToLocal(msg);
}

int64_t BlockManager::FixRewardWithHistory(const std::string& id, int64_t new_amount) {
    auto day_tm = common::TimeUtils::TimestampDays();
    std::string key = std::string("ad_reward_day_") + id + "_" + std::to_string(day_tm);
    std::lock_guard<std::mutex> guard(account_reward_map_mutex_);
    auto iter = account_reward_map_.find(key);
    if (iter == account_reward_map_.end()) {
        std::string val;
        auto res = db::Db::Instance()->Get(key, &val);
        if (res.ok()) {
            uint64_t tmp_val = 0;
            common::StringUtil::ToUint64(val, &tmp_val);
            account_reward_map_[key] = tmp_val;
            iter = account_reward_map_.find(key);
        } else {
            account_reward_map_[key] = new_amount;
            db::Db::Instance()->Put(key, std::to_string(new_amount));
            return new_amount;
        }
    }

    if (iter->second > 5) {
        new_amount = rand() % 2;
    }

    if (iter->second > 10) {
        new_amount = rand() % 3;
        if (new_amount == 0) {
            new_amount = rand() % 3;
        } else {
            new_amount = 0;
        }
    }

    if (iter->second > 30) {
        new_amount = rand() % 5;
        if (new_amount == 0) {
            new_amount = rand() % 3;
        } else {
            new_amount = 0;
        }
    }

    if (iter->second > 100) {
        return 0;
    }

    if (new_amount <= 0) {
        return 0;
    }

    iter->second += new_amount;
    db::Db::Instance()->Put(key, std::to_string(iter->second));
    return new_amount;
}

void BlockManager::HandleGetAccountInitRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    BLOCK_ERROR("get account init request coming: %s",
        common::Encode::HexEncode(block_msg.account_init_req().id()).c_str());
    auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
            block_msg.account_init_req().id());
    if (account_ptr == nullptr) {
        return;
    }

    protobuf::BlockMessage block_res;
    auto account_init_res = block_res.mutable_account_init_res();
    uint64_t balance = 0;
    account_ptr->GetBalance(&balance);
    account_init_res->set_balance(balance);
    account_init_res->set_id(block_msg.account_init_req().id());
    uint32_t count = 0;
    auto height_blocks = account_ptr->GetHeightBlockInfos(&count);
    for (uint32_t i = 0; i < count; ++i) {
        if (height_blocks[i].item->height <= block_msg.account_init_req().height()) {
            continue;
        }

        auto tx_info = account_init_res->add_tx_list();
        tx_info->set_height(height_blocks[i].item->height);
        tx_info->set_timestamp(height_blocks[i].item->timestamp);
        tx_info->set_from(height_blocks[i].item->from);
        tx_info->set_to(height_blocks[i].item->to);
        if (header.version() <= transport::kTransportTxBignumVersionNum) {
            tx_info->set_amount(height_blocks[i].item->amount);
            tx_info->set_balance(height_blocks[i].item->balance);
        } else {
            tx_info->set_amount(height_blocks[i].item->amount);
            tx_info->set_balance(height_blocks[i].item->balance);
        }

        tx_info->set_gid(height_blocks[i].item->gid);
        tx_info->set_type(height_blocks[i].item->type);
        tx_info->set_status(height_blocks[i].item->status);
        tx_info->set_version(height_blocks[i].item->version);
    }

    DHT_ERROR("get account tx list size: %u", account_init_res->tx_list_size());
    if (account_init_res->tx_list_size() <= 0) {
        return;
    }

    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_res.SerializeAsString(),
            msg);
    DHT_ERROR("get account tx list size: %u, from: %s:%d",
        account_init_res->tx_list_size(), header.from_ip().c_str(), header.from_port());
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

void BlockManager::HandleGetHeightRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    auto acc_ptr = AccountManager::Instance()->GetAcountInfo(
            block_msg.height_req().account_addr());
    if (acc_ptr == nullptr) {
        return;
    }
    protobuf::BlockMessage block_msg_res;
    auto height_res = block_msg_res.mutable_height_res();
	height_res->set_account_addr(block_msg.height_req().account_addr());
    uint64_t db_height = 0;
    std::vector<uint64_t> res;
    acc_ptr->GetTxHeights(&res);
    for (uint32_t i = 0; i < res.size(); ++i) {
        height_res->add_heights(res[i]);
    }

    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

void BlockManager::SendBlockNotExists(transport::protobuf::Header& header) {
    protobuf::BlockMessage block_msg_res;
    auto block_res = block_msg_res.mutable_block_res();
    block_res->set_block("");
    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

int BlockManager::HandleGetBlockRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    std::string block_hash;
    if (block_msg.block_req().has_block_hash()) {
        block_hash = block_msg.block_req().block_hash();
    } else if (block_msg.block_req().has_tx_gid()) {
        std::string tx_gid;
        if (block_msg.block_req().from()) {
            tx_gid = common::GetTxDbKey(true, block_msg.block_req().tx_gid());
        } else {
            tx_gid = common::GetTxDbKey(false, block_msg.block_req().tx_gid());
        }
        auto st = db::Db::Instance()->Get(tx_gid, &block_hash);
        if (!st.ok()) {
            SendBlockNotExists(header);
            return kBlockError;
        }
    } else if (block_msg.block_req().has_height()) {
        auto acc_ptr = AccountManager::Instance()->GetAcountInfo(
                block_msg.block_req().account_address());
        if (acc_ptr == nullptr) {
            SendBlockNotExists(header);
            return kBlockError;
        }

        if (acc_ptr->GetBlockHashWithHeight(
                block_msg.block_req().height(),
                &block_hash) != block::kBlockSuccess) {
            SendBlockNotExists(header);
            return kBlockError;
        }
    }

    if (block_hash.empty()) {
        SendBlockNotExists(header);
        return kBlockError;
    }

    std::string* block_data = new std::string();
    auto st = db::Db::Instance()->Get(block_hash, block_data);
    if (!st.ok()) {
        delete block_data;
        SendBlockNotExists(header);
        return kBlockError;
    }

//     BLOCK_ERROR("HandleGetBlockRequest with height OK[%s:%d] "
//             "block_msg.block_req().has_block_hash(): %d, "
//             "block_msg.block_req().has_tx_gid(): %d£¬ "
//             "block_msg.block_req().has_height(): %d, "
//             "%s: %llu, hash[%s]",
//             header.from_ip().c_str(),
//             header.from_port(),
//             block_msg.block_req().has_block_hash(),
//             block_msg.block_req().has_tx_gid(),
//             block_msg.block_req().has_height(),
//             common::Encode::HexEncode(block_msg.block_req().account_address()).c_str(),
//             block_msg.block_req().height(),
//             common::Encode::HexEncode(block_hash).c_str());
//     if (block_msg.block_req().has_height()) {
//         SaveHeightBlockWithCache(block_msg.block_req().height(), block_data);
//     }

    SendBlockResponse(header, *block_data);
    return kBlockSuccess;
}

void BlockManager::SendBlockResponse(
        transport::protobuf::Header& header,
        const std::string& block_data) {
    protobuf::BlockMessage block_msg_res;
    auto block_res = block_msg_res.mutable_block_res();
    block_res->set_block(block_data);
    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    if (header.has_transport_type() && header.transport_type() == transport::kTcp) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    } else {
        transport::MultiThreadHandler::Instance()->transport()->Send(
                header.from_ip(), header.from_port(), 0, msg);
    }
}

int BlockManager::AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_item) {
    {
        std::lock_guard<std::mutex> guard(block_hash_limit_set_mutex_);
        if (!block_hash_limit_set_.Push(block_item->hash())) {
            return kBlockError;
        }
    }
    db::DbWriteBach db_batch;
//     BLOCK_DEBUG("add block hash: %s", common::Encode::HexEncode(block_item->hash()).c_str());
    std::string height_db_key = common::GetHeightDbKey(
        block_item->network_id(),
        block_item->pool_index(),
        block_item->height());
    db_batch.Put(height_db_key, block_item->hash());
    std::string block_str;
    if (!block_item->SerializeToString(&block_str)) {
        return kBlockError;
    }

    db_batch.Put(block_item->hash(), block_str);
    AccountManager::Instance()->AddBlockItem(block_item, db_batch);
    auto st = db::Db::Instance()->Put(db_batch);
    if (!st.ok()) {
        exit(0);
    }

    return kBlockSuccess;
}

int BlockManager::GetBlockWithHeight(
        uint32_t network_id,
        uint32_t pool_index,
        uint64_t height,
        bft::protobuf::Block& block_item) {
    std::string height_db_key = common::GetHeightDbKey(
        network_id,
        pool_index,
        height);
    std::string block_hash;
    auto st = db::Db::Instance()->Get(height_db_key, &block_hash);
    if (!st.ok()) {
        return kBlockError;
    }

    std::string block_str;
    st = db::Db::Instance()->Get(block_hash, &block_str);
    if (!st.ok()) {
        return kBlockError;
    }

    if (!block_item.ParseFromString(block_str)) {
        return kBlockError;
    }

    return kBlockSuccess;
}

}  // namespace block

}  // namespace tenon
