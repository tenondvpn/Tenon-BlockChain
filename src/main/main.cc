#include <iostream>
#include <queue>
#include <vector>

#include "common/log.h"
#include "init/init_utils.h"
#include "init/network_init.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    tenon::init::NetworkInit net_init;
    tenon::common::SignalRegister();
    if (net_init.Init(argc, argv) != tenon::init::kInitSuccess) {
        net_init.Destroy();
        std::cout << "exit now." << std::endl;
        exit(1);
    }
    return 0;
}
