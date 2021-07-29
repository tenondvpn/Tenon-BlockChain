#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace broadcast {
    class Broadcast;
    typedef std::shared_ptr<Broadcast> BroadcastPtr;
}  // namespace broadcast

namespace network {

class Route {
public:
    static Route* Instance();
    int Send(const transport::protobuf::Header& message);
    int SendToLocal(const transport::protobuf::Header& message);
    void RegisterMessage(uint32_t type, transport::MessageProcessor proc);
    void UnRegisterMessage(uint32_t type);
    void Init();
    void Destroy();
    dht::BaseDhtPtr GetDht(const std::string& dht_key, bool universal);
    void RouteByUniversal(const transport::protobuf::Header& header);

private:
    Route();
    ~Route();
    void HandleMessage(const transport::TransportMessagePtr& header);
    void HandleDhtMessage(const transport::TransportMessagePtr& header);
    void Broadcast(const transport::protobuf::Header& header);
    void RegRouteByUniversal(const transport::TransportMessagePtr& header);

    transport::MessageProcessor message_processor_[common::kLegoMaxMessageTypeCount];
    broadcast::BroadcastPtr broadcast_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(Route);
};

}  // namespace network

}  // namespace tenon
