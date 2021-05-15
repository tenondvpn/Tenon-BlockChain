#include <iostream>
#include <queue>
#include <vector>

#include "common/log.h"
#include "init/init_utils.h"
#include "init/network_init.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    lego::init::NetworkInit net_init;
    lego::common::SignalRegister();
    if (net_init.Init(argc, argv) != lego::init::kInitSuccess) {
        net_init.Destroy();
        std::cout << "exit now." << std::endl;
        exit(1);
    }
    return 0;
}
