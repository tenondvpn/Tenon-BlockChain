// #pragma once
// 
// #include <memory>
// #include <unordered_map>
// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
// #include <assert.h>
// 
// #include "common/time_utils.h"
// #include "transport/tcp/msg_decoder.h"
// #include "transport/tcp/msg_encoder.h"
// #include "transport/tcp/encoder_factory.h"
// #include "transport/tcp/msg_packet.h"
// #include "transport/transport.h"
// #include "mrsocket/mrsocket.h"
// #include "mrsocket/mr_buffer.h"
// #include "mrsocket/mr_code.h"
// 
// namespace lego {
// 
// namespace transport {
// 
// struct User {
//     int id;
//     int type;
//     int fd;
//     int snd_id;
//     int rcv_id;
//     struct mr_buffer* buffer;
// };
// 
// class ClientTransport : public Transport {
// public:
//     ClientTransport(const std::string& ip_port, int backlog, bool create_server);
//     ~ClientTransport();
//     virtual int Init();
//     virtual int Start(bool hold);
//     virtual void Stop();
//     virtual int Send(
//             const std::string& ip,
//             uint16_t port,
//             uint32_t ttl,
//             transport::protobuf::Header& message);
//     virtual int SendToLocal(transport::protobuf::Header& message);
//     virtual int GetSocket();
//     virtual void FreeConnection(const std::string& ip, uint16_t port);
// 
// private:
//     uint64_t GetMessageHash(transport::protobuf::Header& message);
//     struct User* GetConnection(const std::string& ip, uint16_t port);
//     void AddConnection(const std::string& ip, uint16_t port, struct User* stream);
// 
//     EncoderFactory encoder_factory_;
//     void Run();
// 
//     std::shared_ptr<std::thread> run_thread_{ nullptr };
//     std::string ip_port_;
//     std::map<std::string, struct User*> client_connections_;
//     std::mutex conn_map_mutex_;
// };
// }  // namespace transport
// 
// }  // namespace lego
