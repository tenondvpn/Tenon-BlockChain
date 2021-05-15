#include <iostream>
#include <thread>
#include <deque>

#include "common/log.h"
#undef ERROR
#include "common/encode.h"
#include "common/global_info.h"
#include "common/config.h"
#include "common/random.h"
#include "common/country_code.h"
#include "common/split.h"
#include "init/command.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"
#include "lvpn/node_manager.h"
#include "lvpn/local.h"

namespace {

std::deque<std::string> all_prikeys;
std::string GetPrivateKey() {
    FILE* fd = fopen("./prikey", "r");
    if (fd == nullptr) {
        return "";
    }

    char content[2048];
    auto read_len = fread(content, 1, sizeof(content), fd);
    fclose(fd);
    if (read_len <= 0) {
        return "";
    }

    lego::common::Split<> content_split(content, ',', read_len);
    for (uint32_t i = 0; i < content_split.Count(); ++i) {
        if (content_split.SubLen(i) == 64) {
            all_prikeys.push_back(content_split[i]);
        }
    }

    return all_prikeys[0];
}

void SavePrivateKey() {
    FILE* fd = fopen("./prikey", "r");
    if (fd == nullptr) {
        return;
    }

    std::string content;
    for (uint32_t i = 0; i < all_prikeys.size() && i < 3; ++i) {
        content += all_prikeys[i] + ",";
    }

    fwrite(content.c_str(), 1, content.size(), fd);
    fclose(fd);
}

}

int main(int argc, char** argv) {
    std::string des_country = "US";
    if (argc > 1) {
        des_country = argv[1];
    }

    std::string old_private_key = GetPrivateKey();
    lego::common::SignalRegister();
    auto int_res = lego::client::VpnClient::Instance()->Init(
            "0.0.0.0",
            7981,
            "id:42.51.39.113:9001,id:42.51.33.89:9001,id:42.51.41.173:9001, id:113.17.169.103:9001,id:113.17.169.105:9001,id:113.17.169.106:9001,id:113.17.169.93:9001,id:113.17.169.94:9001,id:113.17.169.95:9001,id:216.108.227.52:9001,id:216.108.231.102:9001,id:216.108.231.103:9001,id:216.108.231.105:9001,id:216.108.231.19:9001,id:3.12.73.217:9001,id:3.137.186.226:9001,id:3.22.68.200:9001,id:3.138.121.98:9001,id:18.188.190.127:9001,",
            "./",
            "5.0.0",
            old_private_key);
    if (int_res == "ERROR") {
        std::cout << "init client failed: " << int_res << std::endl;
        return 1;
    }

    lego::common::Split<> content_split(int_res.c_str(), ',', int_res.size());
    if (content_split.Count() < 5) {
        std::cout << "init client failed: " << int_res << std::endl;
        return 1;
    }

    if (old_private_key.empty()) {
        all_prikeys.push_front(content_split[2]);
        SavePrivateKey();
    }

    const std::string tenon_conf_path = "./tenon.json";
    std::string local_country = lego::common::global_code_to_country_map[
            lego::common::GlobalInfo::Instance()->country()];
    int res = lego::lvpn::NodeManager::Instance()->Init(
            tenon_conf_path,
            local_country,
            des_country);
    if (res != lego::lvpn::kLvpnSuccess) {
        std::cout << "init NodeManager failed: " << res << std::endl;
        return 1;
    }

    const int32_t kArgc = 5;
    const char* tenonArgv[64] = {
            "tenonvpn",
            "-c",
            tenon_conf_path.c_str(),
            "--fast-open" ,
            "--reuse-port"
    };

    start_vpn_local(kArgc, (char**)tenonArgv);
    while (true) {
        lego::lvpn::NodeManager::Instance()->ResetNodesFromConf();
        std::this_thread::sleep_for(std::chrono::milliseconds(2000ull));
    }
//     lego::init::Command cmd;
//     if (!cmd.Init(false, true, false)) {
//         std::cout << "init cmd failed!" << std::endl;
//         return 1;
//     }
//     cmd.Run();
    return 0;
}