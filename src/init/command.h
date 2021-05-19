#pragma once

#include <functional>
#include <vector>
#include <mutex>
#include <map>
#include <unordered_set>

#include "common/utils.h"
#include "common/tick.h"

namespace tenon {

namespace init {

typedef std::function<void(const std::vector<std::string>&)> CommandFunction;

class Command {
public:
    Command();
    ~Command();

    bool Init(bool first_node, bool show_cmd, bool period_tick = false);
    void Run();
    void Destroy() { destroy_ = true; }
    void Help();

private:
    struct ConfigNodeInfo {
        std::string country;
        std::string ip;
        std::string pk;
        std::string dht_key;
        uint16_t vpn_port;
    };

    void ProcessCommand(const std::string& cmdline);
    void AddCommand(const std::string& cmd_name, CommandFunction cmd_func);
    void AddBaseCommands();
    void PrintDht(uint32_t network_id);
    void PrintMembers(uint32_t network_id);
    void GetVpnNodes(const std::string& country, bool is_vip);
    void GetRouteNodes(const std::string& country, bool is_vip);
    void TxPeriod();
	void VpnHeartbeat(const std::string& dht_key);
	void CreateNewVpnVersion(const std::string& download_url);
    void SendClientUseBandwidth(const std::string& id, uint32_t bandwidth);
    void FixDb(const std::string& db_path);
    void LevelDbToRocksDb(const std::string& db_path);
    int LoadAllTx(
            const std::string& frist_hash,
            uint32_t netid,
            uint32_t pool_index,
            std::unordered_set<std::string>& added_user_set);
    int LoadAllNodesAndCheckPort();
    int CheckAllNodePortValid();

    static const uint32_t kTransportTestPeriod = 1000 * 1000;
    std::map<std::string, CommandFunction> cmd_map_;
    std::mutex cmd_map_mutex_;
    bool destroy_{ false };
    bool show_cmd_{ false };
    bool first_node_{ false };
    common::Tick tx_tick_;
    std::vector<ConfigNodeInfo> config_node_info_;
    std::set<std::string> config_node_ips_;
};

}  // namespace init

}  // namespace tenon
