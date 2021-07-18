#include "stdafx.h"
#include "contract/contract_vpn_mining.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "db/db_utils.h"
#include "transport/transport_utils.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "dht/dht_key.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "contract/contract_utils.h"
#include "security/secp256k1.h"

namespace tenon {

namespace contract {

static const std::string kVpnMiningStr("Tsdf345SDfSFDdf3453HGdfgasdf2342");

int VpnMining::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    if (tx_info.type() == common::kConsensusVpnMining) {
        return HandleConsensusVpnMining(block_item, tx_info, db_batch);
    }

    if (tx_info.type() == common::kConsensusVpnMiningPayToNode) {
        return HandleConsensusVpnMiningPayForNode(block_item, tx_info, db_batch);
    }

    return kContractSuccess;
}

int VpnMining::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int VpnMining::Execute(bft::TxItemPtr tx_item) {
    if (tx_item->tx.type() != common::kConsensusVpnMining &&
            tx_item->tx.type() != common::kConsensusVpnMiningPayToNode) {
        return kContractError;
    }

    return kContractSuccess;
}

static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(bft::kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(bft::kBftBroadcastStopTimes);
    broad_param->set_hop_limit(bft::kBftHopLimit);
    broad_param->set_hop_to_layer(bft::kBftHopToLayer);
    broad_param->set_neighbor_count(bft::kBftNeighborCount);
}

static void CreateTransaction(
        const dht::NodePtr& local_node,
        const std::string& gid,
        const std::string& to,
        int64_t amount,
        const std::string& attr_key,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key());
    std::string account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(
        security::Schnorr::Instance()->str_pubkey_uncompress());
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from(account_address);
    new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
    new_tx->set_type(common::kConsensusVpnMiningPayToNode);
    new_tx->set_to(to);
    new_tx->set_amount(amount);
    auto server_attr = new_tx->add_attr();
    server_attr->set_key(common::kVpnMiningBandwidth);
    server_attr->set_value(attr_key);
    auto data = tx_bft.SerializeAsString();
    bft_msg.set_data(data);
    auto hash128 = common::Hash::Hash128(data);
    security::Signature sign;
    auto& prikey = *security::Schnorr::Instance()->prikey();
    auto& pubkey = *security::Schnorr::Instance()->pubkey();
    if (!security::Schnorr::Instance()->Sign(
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

void VpnMining::CreateVpnMiningBft(
        const std::string& account_id,
        uint64_t amount,
        const std::string& attr_key) {
    transport::protobuf::Header msg;
    uint64_t rand_num = 0;
    auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    if (uni_dht == nullptr) {
        return;
    }

    auto tx_gid = common::CreateGID(attr_key);
    CreateTransaction(
            uni_dht->local_node(),
            tx_gid,
            account_id,
            amount,
            attr_key,
            msg);
    network::Route::Instance()->Send(msg);
    network::Route::Instance()->SendToLocal(msg);
}

void VpnMining::PayForMiningNode() {
    auto day_tm = common::TimeUtils::TimestampDays();
    std::string begin_item;
    if (!mining_unique_queue_.begin(&begin_item)) {
        CONTRACT_ERROR("get begin item failed!");
        return;
    }

    common::Split<> item_split(begin_item.c_str(), '_', begin_item.size());
    if (item_split.Count() < 3) {
        CONTRACT_ERROR("item_split failed[%s]!", begin_item.c_str());
        return;
    }

    uint64_t b_day_tm = 0;
    if (!common::StringUtil::ToUint64(item_split[2], &b_day_tm)) {
        return;
    }

    if (b_day_tm == day_tm) {
        CONTRACT_ERROR("day tm error[%lu][%lu]!", b_day_tm, day_tm);
        return;
    }

    CONTRACT_ERROR("begin: %s", begin_item.c_str());
    uint64_t all_bandwidth = 0;
    std::string all_val;
    auto res = db::Db::Instance()->Get(
            std::string("contract_pay_for_mining_") + std::to_string(b_day_tm),
            &all_val);
    if (res.ok()) {
        if (!common::StringUtil::ToUint64(all_val, &all_bandwidth)) {
            return;
        }
    }

    if (all_bandwidth == 0) {
        for (auto idx = mining_unique_queue_.begin_index();
                idx != mining_unique_queue_.end_index(); ++idx) {
            std::string tmp_item;
            if (!mining_unique_queue_.get(idx, &tmp_item)) {
                continue;
            }

            CONTRACT_ERROR("all bandwidth handle item %lu: %s", idx, tmp_item.c_str());
            common::Split<> item_split(tmp_item.c_str(), '_', tmp_item.size());
            if (item_split.Count() < 3) {
                continue;
            }

            uint64_t tmp_day_tm = 0;
            if (!common::StringUtil::ToUint64(item_split[2], &tmp_day_tm)) {
                continue;
            }

            if (tmp_day_tm != b_day_tm) {
                continue;
            }

            std::string tmp_val;
            auto item_res = db::Db::Instance()->Get(tmp_item, &tmp_val);
            if (item_res.ok()) {
                uint64_t get_tmp_val = 0;
                if (common::StringUtil::ToUint64(tmp_val, &get_tmp_val)) {
                    all_bandwidth += get_tmp_val;
                }
            }
        }

        db::Db::Instance()->Put(
                std::string("contract_pay_for_mining_") + item_split[2],
                std::to_string(all_bandwidth));
    }

    CONTRACT_ERROR("mining queue size: %d, all bandwidth: %lu", mining_unique_queue_.size(), all_bandwidth);
    uint32_t handled_count = 0;
    uint32_t queue_count = 0;
    for (auto idx = mining_unique_queue_.begin_index();
            idx != mining_unique_queue_.end_index(); ++idx) {
        std::string tmp_item;
        if (!mining_unique_queue_.get(idx, &tmp_item)) {
            continue;
        }

        CONTRACT_ERROR("handle item %lu: %s", idx, tmp_item.c_str());
        common::Split<> item_split(tmp_item.c_str(), '_', tmp_item.size());
        if (item_split.Count() < 3) {
            continue;
        }

        uint64_t tmp_day_tm = 0;
        if (!common::StringUtil::ToUint64(item_split[2], &tmp_day_tm)) {
            continue;
        }

        if (tmp_day_tm != b_day_tm) {
            CONTRACT_ERROR("day tm error[%lu][%lu]!", tmp_day_tm, b_day_tm);
            continue;
        }

        ++queue_count;
        if (!db::Db::Instance()->Exist(tmp_item)) {
            ++handled_count;
            CONTRACT_ERROR("tmp_item[%s] not exists!", tmp_item.c_str());
            continue;
        }

        std::string tmp_band;
        if (!db::Db::Instance()->Get(tmp_item, &tmp_band).ok()) {
            ++handled_count;
            CONTRACT_ERROR("tmp_item[%s] not exists!", tmp_item.c_str());
            continue;
        }

        uint64_t bandwidth_node = 0;
        if (!common::StringUtil::ToUint64(tmp_band, &bandwidth_node)) {
            continue;
        }

        auto to = common::Encode::HexDecode(item_split[1]);
        uint64_t amount = (uint64_t)((double)bandwidth_node / (double)all_bandwidth *
            (double)(4000llu * common::kTenonMiniTransportUnit));
        CreateVpnMiningBft(to, amount, tmp_item);
        CONTRACT_ERROR("new node get mining, node bandwidth: %llu, all bandwidth: %llu, amount: %llu, id: %s",
            bandwidth_node, all_bandwidth, amount, item_split[1]);
    }

    db::DbWriteBach db_batch;
    if (queue_count == handled_count && queue_count > 0) {
        for (auto idx = mining_unique_queue_.begin_index();
                idx != mining_unique_queue_.end_index(); ++idx) {
            std::string tmp_item;
            if (!mining_unique_queue_.get(idx, &tmp_item)) {
                continue;
            }

            common::Split<> item_split(tmp_item.c_str(), '_', tmp_item.size());
            if (item_split.Count() < 3) {
                continue;
            }

            uint64_t tmp_day_tm = 0;
            if (!common::StringUtil::ToUint64(item_split[2], &tmp_day_tm)) {
                continue;
            }

            if (tmp_day_tm != b_day_tm) {
                break;
            }

            mining_unique_queue_.pop(&tmp_item, db_batch);
        }

        db::Db::Instance()->Put(db_batch);
    }
}

void VpnMining::TickPayForMiningNode() {
    if (!common::GlobalInfo::Instance()->is_lego_leader()) {
        return;
    }

    PayForMiningNode();
    mining_pay_for_node_tick_.CutOff(
            10000000llu,
            std::bind(&VpnMining::TickPayForMiningNode, this));
}

int VpnMining::HandleConsensusVpnMining(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    if (tx_info.to_add()) {
        return kContractSuccess;
    }

    auto now_day_timestamp = common::TimeUtils::TimestampDays();
    std::string attr_key = (common::kVpnMiningBandwidth + "_" +
            common::Encode::HexEncode(tx_info.from()) + "_" +
            std::to_string(now_day_timestamp));
    std::string attr_val;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == common::kVpnMiningBandwidth) {
            attr_val = tx_info.attr(i).value();
            break;
        }
    }

    if (attr_val.empty()) {
        return kContractSuccess;
    }

    uint64_t bandwidth = 0;
    if (!common::StringUtil::ToUint64(attr_val, &bandwidth)) {
        return kContractSuccess;
    }

    std::string db_bandwidth;
    auto db_res = db::Db::Instance()->Get(attr_key, &db_bandwidth);
    if (db_res.ok()) {
        uint64_t tmp_band = 0;
        if (common::StringUtil::ToUint64(db_bandwidth, &tmp_band)) {
            bandwidth += tmp_band;
        }
    }

    db_batch.Put(attr_key, std::to_string(bandwidth));
    mining_unique_queue_.push(attr_key, db_batch);
    CONTRACT_ERROR("new server node bandwidth contract coming: %s, %u, %llu",
            common::Encode::HexEncode(tx_info.from()).c_str(),
            bandwidth,
            now_day_timestamp);
    return kContractSuccess;
}

int VpnMining::HandleConsensusVpnMiningPayForNode(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    if (tx_info.to_add()) {
        return kContractSuccess;
    }

    std::string attr_val;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == common::kVpnMiningBandwidth) {
            attr_val = tx_info.attr(i).value();
            break;
        }
    }

    if (attr_val.empty()) {
        return kContractSuccess;
    }

    db_batch.Delete(attr_val);
    CONTRACT_ERROR("HandleConsensusVpnMiningPayForNode coming: %s", attr_val.c_str());
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
