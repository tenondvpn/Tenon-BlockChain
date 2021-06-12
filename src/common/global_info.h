#pragma once

#include <atomic>
#include <string>
#include <mutex>
#include <cassert>
#include <vector>

#include "common/utils.h"
#include "common/hash.h"
#include "common/config.h"
#include "common/encode.h"

namespace tenon {

namespace common {

class GlobalInfo {
public:
    static GlobalInfo* Instance();
    int Init(const common::Config& config);

    uint32_t MessageId() {
        return ++message_id_;
    }

    void set_id(const std::string& id) {
        id_ = id;
        id_string_hash_ = Hash::Hash192(id_);
        id_hash_ = Hash::Hash64(id_);
    }

    const std::string& id() {
        return id_;
    }

    const std::string& id_string_hash() {
        return id_string_hash_;
    }

    uint64_t id_hash() {
        return id_hash_;
    }

    void set_country(uint8_t country) {
        country_ = country;
    }

    uint8_t country() {
        return country_;
    }

    std::string config_local_ip() {
        return config_local_ip_;
    }

    uint16_t config_local_port() {
        return config_local_port_;
    }

    int32_t config_default_stream_limit() {
        return stream_default_limit_;
    }

    void set_config_local_ip(const std::string& ip) {
        config_local_ip_ = ip;
    }

    void set_config_local_port(uint16_t port) {
        config_local_port_ = port;
    }

    uint16_t http_port() {
        return http_port_;
    }

    bool config_first_node() {
        return config_first_node_;
    }

    const std::string& GetVersionInfo() {
        return version_info_;
    }

    std::string gid() {
        return gid_hash_ + std::to_string(gid_idx_.fetch_add(1));
    }

	void set_network_id(uint32_t netid) {
		network_id_ = netid;
	}

	uint32_t network_id() {
		return network_id_;
	}

	void set_consensus_shard_count(uint32_t count) {
		consensus_shard_count_ = count;
	}

	uint32_t consensus_shard_count() {
		return consensus_shard_count_;
	}

    void set_genesis_start() {
        genesis_start_ = true;
    }

    bool genesis_start() {
        return genesis_start_;
    }

    std::string& tcp_spec() {
        return tcp_spec_;
    }

    uint16_t min_svr_port() {
        return min_svr_port_;
    }

    uint16_t max_svr_port() {
        return max_svr_port_;
    }

    uint16_t min_route_port() {
        return min_route_port_;
    }

    uint16_t max_route_port() {
        return max_route_port_;
    }

    uint16_t min_udp_port() {
        return min_udp_port_;
    }

    uint16_t max_udp_port() {
        return max_udp_port_;
    }

    std::vector<uint32_t>& networks() {
        return networks_;
    }

    void set_config_public_port(uint16_t public_port) {
        config_public_port_ = public_port;
    }

    uint16_t config_public_port() {
        return config_public_port_;
    }

    uint32_t node_weight() {
        return node_weight_;
    }

    bool is_vlan_node() {
        return is_vlan_node_;
    }

    uint32_t udp_mtu() {
        return udp_mtu_;
    }

    uint32_t udp_window_size() {
        return udp_window_size_;
    }

    uint32_t version() {
        return 1;
    }

    bool is_lego_leader() {
        return is_lego_leader_;
    }

    bool is_client() {
        return is_client_;
    }

    const std::set<std::string>& vpn_committee_accounts() {
        return vpn_committee_accounts_;
    }

    const std::set<std::string>& share_reward_accounts() {
        return share_reward_accounts_;
    }

    const std::set<std::string>& watch_ad_reward_accounts() {
        return watch_ad_reward_accounts_;
    }

    const std::set<std::string>& vpn_minning_accounts() {
        return vpn_minning_accounts_;
    }

    std::string node_tag() {
        return node_tag_;
    }

    uint64_t now_gas_price() {
        return now_gas_price_;
    }

    uint64_t gas_price() {
        return gas_price_;
    }

private:
    GlobalInfo();
    ~GlobalInfo();

	static const uint32_t kDefaultTestNetworkShardId = 4u;

    std::string id_;
    std::atomic<uint32_t> message_id_{ 0 };
    std::string id_string_hash_;
    uint64_t id_hash_{ 0 };
    uint8_t country_{ 0 };
    std::string config_local_ip_;
    std::string tcp_spec_;
    uint16_t config_local_port_{ 0 };
    bool config_first_node_{ false };
    std::string version_info_;
    std::string gid_hash_;
    std::atomic<uint64_t> gid_idx_{ 0 };
    uint16_t http_port_{ 0 };
    int32_t stream_default_limit_{ 262144 };
    bool genesis_start_{ false };
    uint16_t min_svr_port_{ 0 };
    uint16_t max_svr_port_{ 0 };
    uint16_t min_route_port_{ 0 };
    uint16_t max_route_port_{ 0 };
    uint16_t min_udp_port_{ 0 };
    uint16_t max_udp_port_{ 0 };
    std::vector<uint32_t> networks_;
    uint16_t config_public_port_{ 0 };
    uint32_t node_weight_{ 1 };
    bool is_vlan_node_{ false };
    uint32_t udp_mtu_{ 1440 };
    uint32_t udp_window_size_{ 1024 };
    bool is_lego_leader_{ false };
    bool is_client_{ false };
    std::set<std::string> vpn_committee_accounts_;
    std::set<std::string> share_reward_accounts_;
    std::set<std::string> watch_ad_reward_accounts_;
    std::set<std::string> vpn_minning_accounts_;
    std::string node_tag_;
    volatile uint32_t network_id_{ 0 };
    volatile uint64_t now_gas_price_{ 100llu };
    volatile uint32_t consensus_shard_count_{ 1 };
    volatile uint64_t gas_price_{ 10 };

    DISALLOW_COPY_AND_ASSIGN(GlobalInfo);
};

}  // namespace common

}  // namespace tenon
