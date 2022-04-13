#include "election/nodes_stoke_manager.h"

#include "block/account_manager.h"
#include "block/block_utils.h"
#include "common/global_info.h"
#include "dht/base_dht.h"
#include "election/proto/elect_proto.h"
#include "network/dht_manager.h"
#include "network/network_utils.h"
#include "network/route.h"
#include "timeblock/time_block_manager.h"
#include "transport/multi_thread.h"

namespace tenon {

namespace elect {

NodesStokeManager* NodesStokeManager::Instance() {
    static NodesStokeManager ins;
    return &ins;
}

void NodesStokeManager::SyncAddressStoke(const std::vector<std::string>& addrs) {
    std::map<uint32_t, std::vector<std::pair<std::string, uint64_t>>> sync_map;
    for (auto iter = addrs.begin(); iter != addrs.end(); ++iter) {
        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(*iter);
        if (acc_info == nullptr) {
            continue;
        }

        uint32_t netid = common::kInvalidUint32;
        if (acc_info->GetConsensuseNetId(&netid) != block::kBlockSuccess) {
            continue;
        }

        uint64_t synced_tm_height = 0;
        {
            std::lock_guard<std::mutex> g(sync_nodes_map_mutex_);
            auto synced_iter = sync_nodes_map_.find(*iter);
            if (synced_iter != sync_nodes_map_.end()) {
                if (synced_iter->second.first ==
                        tmblock::TimeBlockManager::Instance()->LatestTimestamp()) {
                    continue;
                }

                synced_tm_height = synced_iter->second.first;
            } else {
                sync_nodes_map_[*iter] = std::make_pair(0, 0);
            }
        }

        auto siter = sync_map.find(netid);
        if (siter != sync_map.end()) {
            siter->second.push_back(std::make_pair(*iter, synced_tm_height));
        } else {
            sync_map[netid] = std::vector<std::pair<std::string, uint64_t>>{
                std::make_pair(*iter, synced_tm_height) };
        }
    }

    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    for (auto iter = sync_map.begin(); iter != sync_map.end(); ++iter) {
        transport::protobuf::Header msg;
        elect::ElectProto::CreateSyncStokeRequest(
            dht->local_node(),
            iter->first + network::kConsensusWaitingShardOffset,
            iter->second,
            msg);
        if (msg.has_data()) {
            network::Route::Instance()->Send(msg);
        }
    }
}

void NodesStokeManager::GetAddressStoke(const std::string& addr, uint64_t tm_height) {

}

void NodesStokeManager::HandleSyncAddressStoke(
        const transport::protobuf::Header& header,
        const protobuf::ElectMessage& ec_msg) {
    auto dht = network::DhtManager::Instance()->GetDht(
        common::GlobalInfo::Instance()->network_id());
    if (!dht) {
        return;
    }

    transport::protobuf::Header msg;
    msg.set_src_dht_key(dht->local_node()->dht_key());
    msg.set_des_dht_key(dht->local_node()->dht_key());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kElectMessage);
    msg.set_client(false);
    msg.set_universal(false);
    msg.set_hop_count(0);

    // now just for test
    protobuf::ElectMessage res_ec_msg;
    auto sync_stoke_res = res_ec_msg.mutable_sync_stoke_res();
    for (int32_t i = 0; i < ec_msg.sync_stoke_req().sync_item_size(); ++i) {
        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(
            ec_msg.sync_stoke_req().sync_item(i).id());
        if (acc_info == nullptr) {
            continue;
        }

        std::string block_str;
        acc_info->GetAccountTmHeightBlock(
            ec_msg.sync_stoke_req().now_tm_height(),
            ec_msg.sync_stoke_req().sync_item(i).synced_tm_height(),
            &block_str);
        if (!block_str.empty()) {
            auto block_item = std::make_shared<bft::protobuf::Block>();
            if (!block_item->ParseFromString(block_str)) {
                continue;
            }

            auto& tx_list = block_item->tx_list();
            for (int32_t i = 0; i < tx_list.size(); ++i) {
                std::lock_guard<std::mutex> g(sync_nodes_map_mutex_);
                std::string addr;
                if (tx_list[i].to_add()) {
                    if (ec_msg.sync_stoke_req().sync_item(i).id() != tx_list[i].to()) {
                        continue;
                    }

                    addr = tx_list[i].to();
                } else {
                    if (ec_msg.sync_stoke_req().sync_item(i).id() != tx_list[i].from()) {
                        continue;
                    }

                    addr = tx_list[i].from();
                }

                auto res_item = sync_stoke_res->add_items();
                res_item->set_id(addr);
                res_item->set_balance(tx_list[i].balance());
            }
        }
    }

    sync_stoke_res->set_now_tm_height(ec_msg.sync_stoke_req().now_tm_height());
    msg.set_data(res_ec_msg.SerializeAsString());
    transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
        header.from_ip(), header.from_port(), 0, msg);
}

void NodesStokeManager::HandleSyncStokeResponse(
        const transport::protobuf::Header& header,
        const protobuf::ElectMessage& ec_msg) {
    for (int32_t i = 0; i < ec_msg.sync_stoke_res().items_size(); ++i) {
        std::lock_guard<std::mutex> g(sync_nodes_map_mutex_);
        auto iter = sync_nodes_map_.find(ec_msg.sync_stoke_res().items(i).id());
        if (iter == sync_nodes_map_.end()) {
            continue;
        }

        sync_nodes_map_[ec_msg.sync_stoke_res().items(i).id()] = std::make_pair(
            ec_msg.sync_stoke_res().now_tm_height(),
            ec_msg.sync_stoke_res().items(i).balance());
    }
}

}  // namespace elect

}  // namespace tenon
