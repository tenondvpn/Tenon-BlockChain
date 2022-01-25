#include "services/bandwidth_manager.h"

#include "common/split.h"
#include "transport/transport_utils.h"
#include "security/security.h"
#include "security/secp256k1.h"
#include "dht/dht_key.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "contract/contract_utils.h"
#include "network/universal_manager.h"
#include "network/network_utils.h"
#include "network/route.h"
#include "services/vpn_server/vpn_svr_utils.h"

namespace tenon {

namespace service {

BandwidthManager* BandwidthManager::Instance() {
    static BandwidthManager ins;
    return &ins;
}

void BandwidthManager::AddServerBandwidth(int32_t bandwidth) {
    server_bandwidth_queue_.push(bandwidth);
}

void BandwidthManager::AddRouteBandwidth(int32_t bandwidth) {
    route_bandwidth_queue_.push(bandwidth);
}

void BandwidthManager::FlushToDb() {
    db::DbWriteBach db_batch;
    CheckAccountValid(db_batch);
    CheckServerBandwidth(db_batch);
    CheckRouteBandwidth(db_batch);
    BandwidthProv(db_batch);
    db::Db::Instance()->Put(db_batch);
    flush_to_db_tick_.CutOff(kFlushDbPeriod, std::bind(&BandwidthManager::FlushToDb, this));
}

BandwidthManager::BandwidthManager() {
    std::string val;
    auto res = db::Db::Instance()->Get("tvpn_local_prev_flush_to_bft_tm", &val);
    if (res.ok()) {
        common::StringUtil::ToUint64(val, &prev_flush_to_bft_tm_);
    }

    res = db::Db::Instance()->Get("tvpn_svr_node_bw", &val);
    if (res.ok()) {
        common::StringUtil::ToUint64(val, &svr_bandwidth_all_);
    }

    res = db::Db::Instance()->Get("tvpn_route_node_bw", &val);
    if (res.ok()) {
        common::StringUtil::ToUint64(val, &route_bandwidth_all_);
    }

    FlushToDb();
}

BandwidthManager::~BandwidthManager() {

}

void BandwidthManager::CheckServerBandwidth(db::DbWriteBach& db_batch) {
    int32_t bandwidth;
    while (server_bandwidth_queue_.pop(&bandwidth)) {
        svr_bandwidth_all_ += bandwidth;
    }

    db_batch.Put("tvpn_svr_node_bw", std::to_string(svr_bandwidth_all_));
    VPNSVR_ERROR("CheckServerBandwidth svr_bandwidth_all_: %lu", svr_bandwidth_all_);
}

void BandwidthManager::CheckRouteBandwidth(db::DbWriteBach& db_batch) {
    int32_t bandwidth;
    while (route_bandwidth_queue_.pop(&bandwidth)) {
        route_bandwidth_all_ += bandwidth;
    }

    db_batch.Put("tvpn_route_node_bw", std::to_string(route_bandwidth_all_));
    VPNSVR_ERROR("CheckRouteBandwidth route_bandwidth_all_: %lu", route_bandwidth_all_);
}

void BandwidthManager::AddClientBandwidthInfo(BandwidthInfoPtr& client_bandwith) {
//     bandwidth_queue_.push(client_bandwith);
}

void BandwidthManager::CheckAccountValid(db::DbWriteBach& db_batch) {
    auto day_tm = common::TimeUtils::TimestampDays();
    BandwidthInfoPtr account_info = nullptr;
    while (bandwidth_queue_.pop(&account_info)) {
        if (account_info != nullptr) {
            std::string item_key = account_info->account_id + "_" + std::to_string(day_tm);
            user_day_unique_queue_.push(item_key, db_batch);
            account_info->join_time = std::chrono::steady_clock::now();
            auto iter = user_bandwidth_map_.find(item_key);
            if (iter == user_bandwidth_map_.end()) {
                user_bandwidth_map_[item_key] = account_info;
            }            

            user_bandwidth_map_[item_key]->today_used_bandwidth += account_info->down_bandwidth;
            user_bandwidth_map_[item_key]->today_used_bandwidth += account_info->up_bandwidth;
            db::Dict::Instance()->Hset(
                    "tvpnub",
                    item_key,
                    std::to_string(user_bandwidth_map_[item_key]->today_used_bandwidth),
                    db_batch);
        }
    }
}

void BandwidthManager::BandwidthProv(db::DbWriteBach& db_batch) {
    auto now_sec_tm = common::TimeUtils::TimestampSeconds();
    // flush to bft per hour
    if (now_sec_tm - prev_flush_to_bft_tm_ < 3600lu) {
        return;
    }

    BftForLocalNodePassedBandwidth();
    prev_flush_to_bft_tm_ = now_sec_tm;
}

static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;

static void CreateMiningContract(
        const dht::NodePtr& local_node,
        const std::string& gid,
        int64_t bandwidth,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
            security::Security::Instance()->str_pubkey());
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_pubkey(security::Security::Instance()->str_pubkey());
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from(account_address);
    new_tx->set_from_pubkey(security::Security::Instance()->str_pubkey());
    new_tx->set_type(common::kConsensusVpnMining);
    auto server_attr = new_tx->add_attr();
    server_attr->set_key(common::kVpnMiningBandwidth);
    server_attr->set_value(std::to_string(bandwidth));
    auto data = tx_bft.SerializeAsString();
    bft_msg.set_data(data);
    auto hash128 = common::Hash::Hash128(data);
    security::Signature sign;
    auto& prikey = *security::Security::Instance()->prikey();
    auto& pubkey = *security::Security::Instance()->pubkey();
    if (!security::Security::Instance()->Sign(
            hash128,
            prikey,
            pubkey,
            sign)) {
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    std::string s_data = bft_msg.SerializeAsString();
    msg.set_data(s_data);
}

void BandwidthManager::BftForLocalNodePassedBandwidth() {
    if (svr_bandwidth_all_ + route_bandwidth_all_ <= 0) {
        return;
    }

    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }

    auto tx_gid = common::CreateGID(security::Security::Instance()->str_pubkey());
    uint32_t type = common::kConsensusVpnMining;
    CreateMiningContract(
            uni_dht->local_node(),
            tx_gid,
            svr_bandwidth_all_ + route_bandwidth_all_,
            msg);
    if (msg.has_data() && !msg.data().empty()) {
        network::Route::Instance()->Send(msg);
        VPNSVR_ERROR("BftForLocalNodePassedBandwidth called: %lu", (svr_bandwidth_all_ + route_bandwidth_all_));
        svr_bandwidth_all_ = 0;
        route_bandwidth_all_ = 0;
    } else {
        VPNSVR_ERROR("failed BftForLocalNodePassedBandwidth called: %lu", (svr_bandwidth_all_ + route_bandwidth_all_));
    }
}

}  // namespace service

}  // namespace tenon
