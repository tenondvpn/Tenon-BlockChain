#include <iostream>
#include <thread>

#include "common/log.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/config.h"
#include "common/random.h"
#include "init/command.h"
#include "ip/ip_with_country.h"
#include "db/db.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
//#define ENCODE_CONFIG_CONTENT
#ifdef ENCODE_CONFIG_CONTENT
    lego::common::SignalRegister();
    auto int_res = lego::client::VpnClient::Instance()->Init(
            "0.0.0.0",
            2,
            "id:134.209.184.49:7896",
            "./conf/",
            "3.0.0",
            "");
    if (int_res == "ERROR") {
        return 1;
    }
#else
    lego::common::Config conf;
    if (!conf.Init("./conf/lego.conf")) {
        return 1;         
    }

    std::string db_path;
    conf.Get("db", "path", db_path);
    auto st = lego::db::Db::Instance()->Init(db_path);
    if (!st) {
        return 1;
    }

    std::string local_ip;
    conf.Get("lego", "local_ip", local_ip);
    uint16_t local_port;
    conf.Get("lego", "local_port", local_port);
    std::string bootstrap;
    conf.Get("lego", "bootstrap", bootstrap);
    bool show_cmd;
    conf.Get("lego", "show_cmd", show_cmd);
    bool run_tx = false;
    conf.Get("lego", "run_tx", run_tx);
    lego::common::SignalRegister();
    if (lego::ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != lego::ip::kIpSuccess) {
        return 1;
    }


    auto int_res = lego::client::VpnClient::Instance()->Init(
            local_ip,
            2,
            bootstrap,
            "./conf/",
            "3.0.0",
            "");
    if (int_res == "ERROR") {
        return 1;
    }
#endif
    lego::init::Command cmd;
    if (!cmd.Init(false, true, false)) {
        return 1;
    }
    cmd.Run();
    return 0;
}