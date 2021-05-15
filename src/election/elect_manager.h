#pragma once

#include <mutex>
#include <memory>
#include <map>

#include "common/utils.h"
#include "transport/proto/transport.pb.h"
#include "network/shard_network.h"
#include "election/elect_utils.h"
#include "election/proto/elect.pb.h"

namespace lego {

namespace elect {

typedef network::ShardNetwork<ElectDht> ElectNode;
typedef std::shared_ptr<ElectNode> ElectNodePtr;

class ElectManager {
public:
    ElectManager();
    ~ElectManager();
    int Join(uint32_t network_id);
    int Quit(uint32_t network_id);

private:
    void HandleMessage(transport::protobuf::Header& header);
    void ProcessNewElectBlock(
            transport::protobuf::Header& header,
            protobuf::ElectMessage& elect_msg,
            bool load_from_db);
    void SaveElectBlock(transport::protobuf::Header& header);
    void LoadElectBlock();

    // visit not frequently, just mutex lock
    std::map<uint32_t, ElectNodePtr> elect_network_map_;
    std::mutex elect_network_map_mutex_;
    std::shared_ptr<ElectNode> elect_node_ptr_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(ElectManager);
};

}  // namespace elect

}  // namespace lego
