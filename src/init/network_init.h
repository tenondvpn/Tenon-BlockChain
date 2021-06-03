#pragma once

#include "common/utils.h"
#include "common/config.h"
#include "common/parse_args.h"
#include "common/tick.h"
#include "transport/transport.h"
#include "init/command.h"

namespace tenon {

namespace root {
	class RootInit;
	typedef std::shared_ptr<RootInit> RootInitPtr;
}  // namespace root

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
    int CreateConfigNetwork();
    int InitBft();
    void CreateNewTx();
    void CreateNewElectBlock();
    int SetPriAndPubKey(const std::string& prikey);
    int InitBlock(const common::Config& conf);
    void TestStartBft();
    void StartMoreServer();

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
    common::Tick test_new_account_tick_;
    common::Tick test_new_elect_tick_;
    common::Tick test_start_bft_tick_;
    bool ec_block_ok_{ false };
	root::RootInitPtr root_{ nullptr };
    std::string config_path_;
    std::set<uint16_t> started_port_set_;

    DISALLOW_COPY_AND_ASSIGN(NetworkInit);
};

}  // namespace init

}  // namespace tenon
