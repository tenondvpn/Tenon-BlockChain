#pragma once

#include <deque>

#include "common/tick.h"
#include "common/config.h"
#include "common/user_property_key_define.h"
#include "transport/proto/transport.pb.h"
#include "client/vpn_client.h"
#include "dht/proto/dht.pb.h"
#include "block/db_account_info.h"
#include "init/init_utils.h"

namespace tenon {

namespace common {

template<>
inline uint64_t MinHeapUniqueVal(const bft::protobuf::TxInfo& val) {
    return common::Hash::Hash64(val.gid());
}

inline bool operator<(bft::protobuf::TxInfo& lhs, bft::protobuf::TxInfo& rhs) {
    return lhs.height() < rhs.height();
}

}  // namespace common


namespace init {

typedef client::VpnServerNode VpnServerNode;
typedef client::VpnServerNodePtr VpnServerNodePtr;
struct ConfigNodeInfo {
    std::string country;
    std::string ip;
    std::string pk;
    std::string dht_key;
};

class UpdateVpnInit {
public:
    static UpdateVpnInit* Instance();
    void GetInitMessage(
            const std::string& account_id,
            dht::protobuf::InitMessage& init_msg,
            const std::string& uid,
            uint32_t trans_version);
    void SetVersionInfo(const std::string& ver);
    void ServerInit(const common::Config& conf);
    uint64_t max_free_bandwidth() {
        return max_free_bandwidth_;
    }

    uint64_t max_vip_bandwidth() {
        return max_vip_bandwidth_;
    }

    std::string GetVersion() {
        return ver_buf_[valid_idx_];
    }

    bool InitSuccess();
    void BootstrapInit(const dht::protobuf::InitMessage& init_msg);
	void GetVpnSvrNodes(
            bool is_vip,
			const std::string& country,
			std::vector<VpnServerNodePtr>& nodes);
	void GetRouteSvrNodes(
            bool is_vip,
            const std::string& country,
			std::vector<VpnServerNodePtr>& nodes);
    void GetVlanVpnNode(
            const std::string& country,
            std::vector<VpnServerNodePtr>& nodes);
    void GetVlanRouteNode(
            const std::string& country,
            const std::string& key,
            std::vector<VpnServerNodePtr>& nodes);
    void GetInitInfo(std::string* init_info);
    void UpdateNodePorts(
            const std::string& dht_key,
            uint16_t min_r_port,
            uint16_t max_r_port,
            uint16_t min_s_port,
            uint16_t max_s_port);
    void AddNode(const std::string& dht_key, VpnServerNodePtr& node);
    void GetAccountInitBlocks(const std::string& account_id, std::string* res);
    void UpdateAccountBlockInfo(const std::string& block_str);
    std::string GetAllNodes(bool is_vip);

    int64_t GetBalance() {
        return init_balance_;
    }

    uint64_t GetMaxHeight() {
        return max_height_;
    }

    common::LimitHeap<bft::protobuf::TxInfo> GetTxBlocks() {
        std::lock_guard<std::mutex> guard(init_blocks_mutex_);
        return init_blocks_;
    }

    std::string init_vpn_count_info() {
        std::lock_guard<std::mutex> guard(init_vpn_count_info_mutex_);
        return init_vpn_count_info_;
    }

    std::string local_vpn_count_direct_info() {
        std::lock_guard<std::mutex> guard(init_vpn_count_info_mutex_);
        return local_vpn_count_direct_info_;
    }

    bool IsValidConfitVpnNode(const std::string ip) {
        return config_node_ips_.find(ip) != config_node_ips_.end();
    }

    uint64_t max_pay_for_vpn_tm() {
        return max_pay_for_vpn_tm_;
    }

    int64_t max_pay_for_vpn_amount() {
        return max_pay_for_vpn_amount_;
    }

    int GetBftNode(std::string* ip, uint16_t* port) {
        std::lock_guard<std::mutex> guard(bft_nodes_mutex_);
        if (bft_nodes_vec_.empty()) {
            return kInitError;
        }
        auto rand_idx = rand() % bft_nodes_vec_.size();
        *ip = bft_nodes_vec_[rand_idx].first;
        *port = bft_nodes_vec_[rand_idx].second;
        return kInitSuccess;
    }

    int GetPortRangeByDhtKey(
        const std::string& dht_key,
        bool is_route,
        uint16_t* min_port,
        uint16_t* max_port);

private:
    UpdateVpnInit();
    ~UpdateVpnInit();
    void GetVpnNodes();
    void GetNetworkNodes(
            const std::vector<std::string>& country_vec,
            uint32_t network_id);
    void HandleNodes(bool is_route, const dht::protobuf::VpnNodeInfo& vpn_node);
    void UpdateBlackNode();
    bool IsBlackIp(const std::string& ip);
    bool IsInvalidNode(const std::string& id, bool route);
    void CheckSeverValid();
    void CreateVlanRleayNodes(dht::protobuf::InitMessage& init_msg);
    void HandleRelayNodes(
            const std::string& country,
            const dht::protobuf::VpnNodeInfo& vpn_node,
            VpnServerNodePtr& route_node_ptr);
    std::string GetBftNodes();
    void HandleBftNodes(const std::string& nodes);
    void SetInitNodeInfo(
            const std::vector<init::VpnServerNodePtr>& node_vec,
            std::vector<int>& pos_vec,
            const std::string& country,
            bool is_vpn,
            bool is_vip,
            dht::protobuf::InitMessage& init_msg);
    void AddToVpnMap(const std::string& country, VpnServerNodePtr& node_ptr);
    void AddToRouteMap(const std::string& country, VpnServerNodePtr& node_ptr);

    static const uint32_t kGetVpnNodesPeriod = 2 * 1000 * 1000;
    static const uint32_t kUpdateBlackNodesPeriod = 10 * 1000 * 1000;
    static const uint32_t kMaxGetVpnNodesNum = 4u;
    static const uint32_t kMaxGetVpnNodesEachCountryNum = 4u;
    static const uint32_t kMaxRelayCount = 16;

    common::Tick check_ver_tick_;
    common::Tick update_vpn_nodes_tick_;
    common::Tick update_black_nodes_tick_;
    std::string ver_buf_[2];
    uint32_t valid_idx_{ 0 };
    std::map<std::string, std::deque<VpnServerNodePtr>> vpn_nodes_map_;
    std::map<std::string, std::deque<VpnServerNodePtr>> vip_vpn_nodes_map_;
    std::map<std::string, VpnServerNodePtr> vpn_dht_key_node_map_;
    std::mutex vpn_nodes_map_mutex_;
    std::map<std::string, std::deque<VpnServerNodePtr>> route_nodes_map_;
    std::map<std::string, std::deque<VpnServerNodePtr>> vip_route_nodes_map_;
    std::map<std::string, VpnServerNodePtr> route_dht_key_node_map_;
    std::mutex route_nodes_map_mutex_;
    std::vector<std::string> country_vec_;
    std::mutex country_vec_mutex_;
    volatile uint64_t max_free_bandwidth_{ 2048llu * 1024llu * 1024llu };
    volatile uint64_t max_vip_bandwidth_{ 10llu * 1024llu * 1024llu * 1024llu };
    std::set<std::string> block_node_set_;
    std::mutex block_node_set_mutex_;
    std::string init_info_;
    uint32_t init_info_node_count_{ 0 };
    std::mutex init_info_mutex_;
    std::unordered_set<std::string> invalid_route_set_;
    std::mutex invalid_route_set_mutex_;
    std::unordered_set<std::string> invalid_server_set_;
    std::mutex invalid_server_set_mutex_;
    common::Tick check_valid_nodes_tick_;
    std::unordered_map<std::string, VpnServerNodePtr> all_nodes_map_;
    std::mutex all_nodes_map_mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, VpnServerNodePtr>> relay_nodes_map_;
    std::mutex relay_nodes_map_mutex_;
    std::vector<ConfigNodeInfo> config_node_info_;
    std::unordered_map<std::string, ConfigNodeInfo> config_node_map_;
    std::set<std::string> config_node_ips_;
    std::string init_vpn_count_info_;
    std::mutex init_vpn_count_info_mutex_;
    std::map<std::string, VpnServerNodePtr> ip_vpn_node_map_;
    std::mutex ip_vpn_node_map_mutex_;
    std::string vpn_count_direct_info_;
    std::string local_vpn_count_direct_info_;
    std::atomic<int64_t> init_balance_{ -1 };
    std::atomic<uint64_t> max_height_{ 0 };
    common::LimitHeap<bft::protobuf::TxInfo> init_blocks_{ true, 1024 };
    std::mutex init_blocks_mutex_;
    std::atomic<uint64_t> max_pay_for_vpn_height_{ 0 };
    std::atomic<uint64_t> max_pay_for_vpn_tm_{ 0 };
    std::atomic<int64_t> max_pay_for_vpn_amount_{ 0 };
    std::unordered_set<std::string> bft_nodes_;
    std::vector<std::pair<std::string, uint16_t>> bft_nodes_vec_;
    std::mutex bft_nodes_mutex_;
    std::map<std::string, ConfigNodeInfo> joined_vpn_map_;
    std::map<std::string, ConfigNodeInfo> joined_route_map_;
};

}  // namespace init

}  // namespace tenon
