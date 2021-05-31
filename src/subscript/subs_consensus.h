#pragma once

#include "common/tick.h"
#include "bft/proto/bft.pb.h"
#include "init/network_init.h"
#include "network/shard_network.h"
#include "subscript/subs_dht.h"
#include "subscript/subs_utils.h"

namespace tenon {

namespace subs {

typedef network::ShardNetwork<SubsDht> SubsDhtNode;
typedef std::shared_ptr<SubsDhtNode> SubsDhtNodePtr;
typedef std::function<void(const bft::protobuf::Block&)> BlockSubsCallbackFunction;

class SubsConsensus : public init::NetworkInit {
public:
    static SubsConsensus* Instance();
    virtual int Init();
    void AddCallback(BlockSubsCallbackFunction callback);

private:
    SubsConsensus();
    ~SubsConsensus();

    void HandleMessage(transport::protobuf::Header& header);
    int StartSubscription();

    SubsDhtNodePtr subs_node_{ nullptr };
    std::vector<BlockSubsCallbackFunction> callbacks_;
    std::mutex callbacks_mutex_;

    DISALLOW_COPY_AND_ASSIGN(SubsConsensus);
};

}  // namespace vpn

}  // namespace tenon
