#pragma once

#include <map>

#include "lvpn/lvpn_utils.h"
#include "common/tick.h"

namespace tenon {

namespace lvpn {

class NodeManager {
public:
    static NodeManager* Instance();
    int Init(
            const std::string& conf_path,
            const std::string& local_country,
            const std::string& des_country);
    int ChooseVpnNode();
    std::string GetVpnStatus();
    void ResetNodesFromConf();

private:
    NodeManager() {}

    ~NodeManager() {}

    void ParseNodesFromConf();
    void UpdateVersionInfo();
    int GetRouteNode(uint32_t* ip, uint16_t* port);
    int GetExRouteNode(uint32_t* ip, uint16_t* port);
    uint32_t StringIpToInt(const std::string& ip);
    void WriteConfig();
    void ChangeDesCountry();

    common::Tick refresh_conf_tick_;
    common::Tick update_version_tick_;
    common::Tick refresh_des_tick_;
    uint32_t valid_route_idx_{ 0 };
    std::string local_conf_path_;
    std::map<std::string, std::string> ex_route_map_;
    std::mutex ex_route_map_mutex_;
    std::string local_country_{ "CN" };
    std::string des_country_{ "US" };
    uint32_t choosed_vpn_ip_{ 0 };
    uint16_t choosed_vpn_port_{ 0 };
    std::string chossed_seckey_;
    std::string status_path_;
    std::string prev_buy_ip_;
    uint64_t start_time_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(NodeManager);
};

}  // namespace lvpn

}  // namespace tenon
