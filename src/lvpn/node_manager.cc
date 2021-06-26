#include "lvpn/node_manager.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <err.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif // !_WIN32

#ifdef __cplusplus
extern "C" {
#endif
#undef ERROR
#include "lvpn/jconf.h"

#ifdef __cplusplus
}
#endif

#undef min
#undef max
#include "common/split.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/string_utils.h"
#include "common/time_utils.h"
#include "lvpn/lvpn_utils.h"
#include "client/vpn_client.h"

namespace tenon {

namespace lvpn {

#ifdef _WIN32

const wchar_t *GetWC(const char *c) {
    const size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, c, cSize);

    return wc;
}

int inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    int size = sizeof(ss);
    ZeroMemory(&ss, sizeof(ss));
#ifdef _WIN32
    wchar_t src_copy[INET6_ADDRSTRLEN + 1];
    const size_t cSize = strlen(src) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, src, cSize);
    wcsncpy(src_copy, wc, INET6_ADDRSTRLEN + 1);
    delete[]wc;
#else
    char src_copy[INET6_ADDRSTRLEN + 1];
    strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
#endif
    /* stupid non-const API */
    src_copy[INET6_ADDRSTRLEN] = 0;

    if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
        switch (af) {
        case AF_INET:
            *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
            return 1;
        case AF_INET6:
            *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
            return 1;
        }
    }
    return 0;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;

    ZeroMemory(&ss, sizeof(ss));
    ss.ss_family = af;

    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
        break;
    default:
        return NULL;
    }
    /* cannot direclty use &size because of strict aliasing rules */
#ifdef _WIN32
    const size_t cSize = strlen(dst) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, dst, cSize);
    char* res = (WSAAddressToString(
            (struct sockaddr *)&ss,
            sizeof(ss),
            NULL,
            wc,
            &s) == 0) ? dst : NULL;
    delete[]wc;
    return res;
#else
    return (WSAAddressToString(
            (struct sockaddr *)&ss,
            sizeof(ss),
            NULL,
            dst,
            &s) == 0) ? dst : NULL;
#endif
}

#endif // _WIN32

NodeManager* NodeManager::Instance() {
    static NodeManager ins;
    return &ins;
}

int NodeManager::Init(
        const std::string& conf_path,
        const std::string& local_country,
        const std::string& des_country) {
    des_country_ = des_country;
    ChangeDesCountry();
    start_time_ = common::TimeUtils::TimestampMs();
    local_conf_path_ = conf_path;
    status_path_ = "./pristatus";
    ChooseVpnNode();
    WriteConfig();
    ParseNodesFromConf();
    return kLvpnSuccess;
}

void NodeManager::ResetNodesFromConf() {
    uint32_t route_ip = 0;
    uint16_t route_port = 0;
    uint32_t ex_route_ip = 0;
    uint16_t ex_route_port = 0;
    GetRouteNode(&route_ip, &route_port);
    GetExRouteNode(&ex_route_ip, &ex_route_port);
    int invalid_idx = (global_valid_idx + 1) % 2;
    memset(global_conf[invalid_idx].seckey, 0, sizeof(global_conf[invalid_idx].seckey));
    memset(global_conf[invalid_idx].pubkey, 0, sizeof(global_conf[invalid_idx].pubkey));
    memset(global_conf[invalid_idx].enc_method, 0, sizeof(global_conf[invalid_idx].enc_method));
    memcpy(
            (char*)global_conf[invalid_idx].seckey,
            (char*)chossed_seckey_.c_str(),
            chossed_seckey_.size());
    std::string pubkey = client::VpnClient::Instance()->GetPublicKey();
    memcpy(
            (char*)global_conf[invalid_idx].pubkey,
            (char*)pubkey.c_str(),
            pubkey.size());
    memcpy(
            (char*)global_conf[invalid_idx].enc_method,
            (char*)"aes-128-cfb",
            strlen("aes-128-cfb"));
    global_conf[invalid_idx].vpn_ip = choosed_vpn_ip_;
    global_conf[invalid_idx].vpn_port = choosed_vpn_port_;
    global_conf[invalid_idx].route_ip = route_ip;
    global_conf[invalid_idx].route_port = route_port;
    global_conf[invalid_idx].ex_route_ip = 0;
    global_conf[invalid_idx].ex_route_port = 0;
    global_valid_idx = invalid_idx;
}

void NodeManager::ParseNodesFromConf() {
    if (common::TimeUtils::TimestampMs() - start_time_ >= 3600llu * 1000llu) {
        ChooseVpnNode();
        start_time_ = common::TimeUtils::TimestampMs();
    }

    ResetNodesFromConf();
//     refresh_conf_tick_.CutOff(
//             2000000ull,
//             std::bind(&NodeManager::ParseNodesFromConf, this));
}

void NodeManager::UpdateVersionInfo() {
    auto version_str = client::VpnClient::Instance()->CheckVersion();
    common::Split<> ver_split(version_str.c_str(), ',', version_str.size());
    std::string ex_route_tag("er");
    for (uint32_t i = 0; i < ver_split.Count(); ++i) {
        common::Split<> item_split(ver_split[i], ver_split.SubLen(i), ';');
        if (item_split.Count() > 0 && ex_route_tag == item_split[0]) {
            std::lock_guard<std::mutex> guard(ex_route_map_mutex_);
            ex_route_map_.clear();
            common::Split<> data_split(item_split[1], item_split.SubLen(1), '1');
            for (uint32_t route_idx = 0; route_idx < data_split.Count(); ++route_idx) {
                common::Split<> tmp_split(data_split[1], data_split.SubLen(1), '2');
                if (tmp_split.Count() == 2) {
                    ex_route_map_[tmp_split[0]] = tmp_split[1];
                }
            }
        }
    }

    update_version_tick_.CutOff(
            1000000ull,
            std::bind(&NodeManager::UpdateVersionInfo, this));
}

uint32_t NodeManager::StringIpToInt(const std::string& ip) {
    struct in_addr s;
    inet_pton(AF_INET, ip.c_str(), &s);
    return s.s_addr;
}

int NodeManager::ChooseVpnNode() {
    std::vector<client::VpnServerNodePtr> nodes;
    std::string des_cnt;
    client::VpnClient::Instance()->GetVpnServerNodes(des_country_, "", 1, false, false, nodes);
    if (nodes.empty()) {
        return kLvpnError;
    }

    int rand_idx = std::rand() % nodes.size();
    choosed_vpn_ip_ = StringIpToInt(nodes[rand_idx]->ip);
    choosed_vpn_port_ = nodes[rand_idx]->svr_port;
    chossed_seckey_ = nodes[rand_idx]->seckey;
    return kLvpnSuccess;
}

int NodeManager::GetRouteNode(uint32_t* ip, uint16_t* port) {
    std::vector<client::VpnServerNodePtr> nodes;
    client::VpnClient::Instance()->GetVpnServerNodes(local_country_, "", 1, true, false, nodes);
    if (nodes.empty()) {
        return kLvpnError;
    }

    int rand_idx = std::rand() % nodes.size();
    *ip = StringIpToInt(nodes[rand_idx]->ip);
    *port = nodes[rand_idx]->route_port;
    return kLvpnSuccess;
}

int NodeManager::GetExRouteNode(uint32_t* ip, uint16_t* port) {
    if (ip == NULL || port == NULL) {
        return kLvpnError;
    }

    std::vector<client::VpnServerNodePtr> nodes;
    client::VpnClient::Instance()->GetVpnServerNodes("US", "", 1, true, false, nodes);
    if (nodes.empty()) {
        return kLvpnError;
    }

    int rand_idx = std::rand() % nodes.size();
    *ip = StringIpToInt(nodes[rand_idx]->ip);
    *port = nodes[rand_idx]->route_port;
    return kLvpnSuccess;
}

std::string NodeManager::GetVpnStatus() {
    FILE* fp = fopen(status_path_.c_str(), "r");
    if (fp == NULL) {
        LVPN_WARN("open file[%s] to write config failed!", status_path_.c_str());
        return "open local file error.";
    }

    char data[1024];
    size_t n = fread(data, 1, sizeof(data), fp);
    fclose(fp);
    if (n <= 0) {
        LVPN_WARN("read file[%s] to write config failed!", status_path_.c_str());
        return "read local file error.";
    }

    return std::string(data, n);
}

void NodeManager::WriteConfig() {
    auto version_str = client::VpnClient::Instance()->CheckVersion();
    common::Split<> ver_split(version_str.c_str(), ',', version_str.size());
    std::string ex_route_tag("buy_ip");
    std::string buy_ip;
    for (uint32_t i = 0; i < ver_split.Count(); ++i) {
        common::Split<> item_split(ver_split[i], ';', ver_split.SubLen(i));
        if (item_split.Count() >= 2 && ex_route_tag == item_split[0]) {
            buy_ip = item_split[1];
            break;
        }
    }

    if (!buy_ip.empty() && prev_buy_ip_ != buy_ip) {
        prev_buy_ip_ = buy_ip;
        std::string content = std::string("http://") +
                buy_ip + "/chongzhi/" +
                common::Encode::HexEncode(common::GlobalInfo::Instance()->id());
        FILE *fp = fopen("./url", "w");
        if (fp != nullptr) {
            size_t n = fwrite(content.c_str(), 1, content.size(), fp);
            fclose(fp);
            if (n != content.size()) {
                LVPN_WARN("write file[%s] to write config failed!", "./url");
            }
        }
    }

    refresh_conf_tick_.CutOff(
            10000000ull,
            std::bind(&NodeManager::WriteConfig, this));
}

void NodeManager::ChangeDesCountry() {
    FILE* fp = fopen("/var/tmp/tenon", "r");
    if (fp != nullptr) {
        char buf[1024];
        std::set<std::string> black_set;
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            std::string tmp_location = buf;
            common::StringUtil::Trim(tmp_location);
            if (tmp_location.size() == 2 && tmp_location != des_country_) {
                des_country_.swap(tmp_location);
                break;
            }
        }
        fclose(fp);
    }
}

}  // namespace lvpn

}  // namespace tenon
