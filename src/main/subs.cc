#include <iostream>

#include "common/log.h"
#include "subscript/subs_consensus.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    tenon::common::SignalRegister();
    tenon::subs::SubsConsensus::Instance()->Init(argc, argv);
    return 0;
}