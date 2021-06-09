#pragma once

#include <memory>
#include <vector>

#include "common/utils.h"
#include "common/config.h"
#include "dht/dht_utils.h"
#include "network/universal.h"

namespace tenon {

namespace transport {
    class Transport;
    typedef std::shared_ptr<Transport> TransportPtr;
}  // namespace transport

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
    class Node;
    typedef std::shared_ptr<Node> NodePtr;
}  // namespace dht

namespace network {

class UniversalManager {
public:
    static UniversalManager* Instance();
    dht::BaseDhtPtr GetUniversal();
    std::vector<dht::NodePtr> GetSameNetworkNodes(uint32_t network_id, uint32_t count);
    int Init(
        const common::Config& config,
        transport::TransportPtr& transport);
    void Destroy();
    int AddNodeToUniversal(dht::NodePtr& node);

private:
    UniversalManager();
    ~UniversalManager();
    int CreateNetwork(
        uint32_t network_id,
        const common::Config& config,
        transport::TransportPtr& transport);
    void DhtBootstrapResponseCallback(
        dht::BaseDht* dht_ptr,
        const dht::protobuf::DhtMessage& dht_msg);
    int CreateUniversalNetwork(
        const common::Config& config,
        transport::TransportPtr& transport);
    int CreateNodeNetwork(
        const common::Config& config,
        transport::TransportPtr& transport);

    dht::BaseDhtPtr universal_dht_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(UniversalManager);
};

}  // namespace network

}  // namespace tenon
