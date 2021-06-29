#pragma once

#include "common/utils.h"
#include "common/config.h"
#include "common/parse_args.h"
#include "common/tick.h"
#include "transport/transport.h"
#include "init/command.h"

namespace tenon {

namespace init {

class NetworkInit {
public:
    NetworkInit();
    virtual ~NetworkInit();
    virtual int Init(int argc, char** argv);
    virtual void Destroy();

protected:
    int InitConfigWithArgs(int argc, char** argv);
    int InitUdpTransport();
    int InitTcpTransport();
    int InitHttpTransport();
    int ParseParams(int argc, char** argv, common::ParserArgs& parser_arg);
    int ResetConfig(common::ParserArgs& parser_arg);
    int InitNetworkSingleton();
    int InitCommand();
    int InitBft();
    int SetPriAndPubKey(const std::string& prikey);
    int InitBlock(const common::Config& conf);
    void StartMoreServer();
    int GenesisCmd(common::ParserArgs& parser_arg);
    int CheckJoinWaitingPool();

    static const uint32_t kDefaultUdpSendBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultUdpRecvBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultTcpSendBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kDefaultTcpRecvBufferSize = 10u * 1024u * 1024u;
    static const uint32_t kTestCreateAccountPeriod = 100u * 1000u;
    static const int64_t kTestNewElectPeriod = 10ll * 1000ll * 1000ll;

    common::Config conf_;
    transport::TransportPtr transport_{ nullptr };
    transport::TransportPtr tcp_transport_{ nullptr };
    transport::TransportPtr http_transport_{ nullptr };
    bool inited_{ false };
    std::mutex init_mutex_;
    Command cmd_;
    bool ec_block_ok_{ false };
    std::string config_path_;
    std::set<uint16_t> started_port_set_;

    DISALLOW_COPY_AND_ASSIGN(NetworkInit);
};

}  // namespace init

}  // namespace tenon
