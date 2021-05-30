#pragma once

#include <unordered_map>
#include <mutex>

#include "common/tick.h"
#include "election/elect_utils.h"
#include "election/elect_node_detail.h"

namespace tenon {

namespace elect {

class ElectPool {
public:
    ElectPool();
    ~ElectPool();
    void AddNewNode(NodeDetailPtr& node_ptr);
    void RemoveNodes(const std::vector<NodeDetailPtr>& nodes);
    void FtsGetNodes(uint32_t count, std::vector<NodeDetailPtr>& nodes);

private:
    void UpdateNodeHeartbeat();

    std::unordered_map<std::string, NodeDetailPtr> node_map_;
    std::mutex node_map_mutex_;
    common::Tick heartbeat_tick_;
};

};  // namespace elect

};  //  namespace tenon
