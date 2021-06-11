#pragma once

#include <mutex>
#include <memory>
#include <map>

#include "common/utils.h"
#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "network/shard_network.h"
#include "election/elect_utils.h"
#include "election/proto/elect.pb.h"
#include "election/elect_pool_manager.h"

namespace tenon {

namespace elect {

typedef network::ShardNetwork<ElectDht> ElectNode;
typedef std::shared_ptr<ElectNode> ElectNodePtr;

class ElectManager {
public:
    static ElectManager* Instance();
    int Join(uint32_t network_id);
    int Quit(uint32_t network_id);
    int BackupCheckElectConsensusShard(const bft::protobuf::TxInfo& tx_info);
    void ProcessNewElectBlock(
        uint64_t height,
        protobuf::ElectBlock& elect_block,
        bool load_from_db);

private:
    ElectManager();
    ~ElectManager();

    void HandleMessage(transport::protobuf::Header& header);
    void CreateNewElectTx(uint32_t shard_network_id, transport::protobuf::Header* msg);
    void CreateAllElectTx();

    // visit not frequently, just mutex lock
    std::map<uint32_t, ElectNodePtr> elect_network_map_;
    std::mutex elect_network_map_mutex_;
    std::shared_ptr<ElectNode> elect_node_ptr_{ nullptr };
    ElectPoolManager pool_manager_;
    std::atomic<uint64_t> latest_height_{ 0 };
    common::Tick create_elect_block_tick_;

    DISALLOW_COPY_AND_ASSIGN(ElectManager);
};

}  // namespace elect

}  // namespace tenon
