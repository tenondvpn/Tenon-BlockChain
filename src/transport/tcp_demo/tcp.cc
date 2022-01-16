#include "common/global_info.h"
#include "common/time_utils.h"
#include "transport/tcp/tcp_transport.h"
#include "transport/transport_utils.h"
#include "transport/udp/udp_transport.h"
#include "common/parse_args.h"
#include "transport/multi_thread.h"
#include "transport/processor.h"

using namespace tenon;
transport::TransportPtr tcp_ptr = nullptr;

static void HandleMessage(transport::TransportMessagePtr& message_ptr) {
    auto& message = *message_ptr;
    static std::atomic<uint32_t> rcv_cnt(0);
    static auto b_time = tenon::common::TimeUtils::TimestampMs();
    if (message.id() == 0) {
        rcv_cnt = 0;
        b_time = tenon::common::TimeUtils::TimestampMs();
    }

//     if (message.id() == 10) {
//         message.set_id(12);
//         tcp_ptr->Send(message.from_ip(), message.from_port(), 0, message);
//     }

    ++rcv_cnt;
    if (rcv_cnt % 10000 == 0) {
        auto use_time_ms = double(tenon::common::TimeUtils::TimestampMs() - b_time) / 1000.0;
        std::cout << "receive rcv_cnt: " << rcv_cnt << " use time: " << use_time_ms << " ms" << std::endl;
    }
}

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    using namespace tenon::transport;
    using namespace tenon::common;

    ParserArgs args_parser;
    args_parser.AddArgType('a', "ip", kMaybeValue);
    args_parser.AddArgType('p', "port", kMaybeValue);
    args_parser.AddArgType('A', "peer ip", kMaybeValue);
    args_parser.AddArgType('P', "peer port", kMaybeValue);

    std::string tmp_params = "";
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i]) == 0) {
            tmp_params += static_cast<char>(31);
        } else {
            tmp_params += argv[i];
        }
        tmp_params += " ";
    }

    std::string err_pos;
    if (args_parser.Parse(tmp_params, err_pos) != kParseSuccess) {
        std::cout << "parse params failed!" << std::endl;
        return 1;
    }

    std::string local_ip;
    if (args_parser.Get("a", local_ip) != kParseSuccess) {
        std::cout << "param must has a(local ip)." << std::endl;
        return 1;
    }

    uint16_t local_port;
    if (args_parser.Get("p", local_port) != kParseSuccess) {
        std::cout << "param must has p(local port)." << std::endl;
        return 1;
    }

    TransportPtr udp_ptr = nullptr;
    MultiThreadHandler::Instance()->Init(udp_ptr, tcp_ptr);
    static const uint32_t kTestMsgType = kUdpDemoTestMessage;
    std::string tcpsec = local_ip + ":" + std::to_string(local_port);
    Processor::Instance()->RegisterProcessor(kTestMsgType, HandleMessage);
    tcp_ptr = std::make_shared<transport::TcpTransport>(
        tcpsec,
        128,
        true);
    if (tcp_ptr->Init() != transport::kTransportSuccess) {
        printf("init udp transport failed!");
        return 1;
    }

    if (tcp_ptr->Start(false) != transport::kTransportSuccess) {
        printf("start udp transport failed!");
        return 1;
    }

    std::string peer_ip;
    args_parser.Get("A", peer_ip);
    uint16_t peer_port;
    args_parser.Get("P", peer_port);
    while (true) {
        if (!peer_ip.empty()) {
            tenon::transport::protobuf::Header msg;
            msg.set_type(kTestMsgType);
            msg.set_src_dht_key(std::string(32, 'a'));
            msg.set_des_dht_key(std::string(32, 'a'));
            msg.set_data("DDDDDDDDDDDDDDDDDDDDDDDDDDD" + std::to_string(common::TimeUtils::TimestampUs()));
            msg.set_client(false);
            msg.set_id(10);
            auto broad_param = msg.mutable_broadcast();
            transport::SetDefaultBroadcastParam(broad_param);
            tcp_ptr->Send(peer_ip, peer_port, 0, msg);
        }

        usleep(100);
    }

    return 0;
}