#pragma once

#include "election/elect_pool.h"
#include "election/proto/elect.pb.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace elect {

class ElectPoolManager {
public:
    ElectPoolManager();
    ~ElectPoolManager();
    void NetworkMemberChange(uint32_t network_id, MembersPtr& members_ptr);
    void UpdateNodeInfoWithBlock(const bft::protobuf::Block& block_info);
    int LeaderCreateElectionBlockTx(
        uint32_t shard_netid,
        bft::protobuf::BftMessage& bft_msg);
    int BackupCheckElectionBlockTx(const bft::protobuf::BftMessage& bft_msg);

private:
    int GetAllLeaderBloomFiler(
        const bft::protobuf::TxInfo& tx_info,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        elect::protobuf::ElectBlock* ec_block);
    int GetAllBloomFilerAndNodes(
        uint32_t shard_netid,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        std::vector<NodeDetailPtr>& exists_shard_nodes,
        std::vector<NodeDetailPtr>& weed_out_vec,
        std::vector<NodeDetailPtr>& pick_in_vec);

    static const uint32_t kBloomfilterHashCount = 7u;
    static const uint32_t kBloomfilterSize = 20480u;
    static const uint32_t kBloomfilterWaitingSize = 40960u;
    static const uint32_t kBloomfilterWaitingHashCount = 9u;

    std::unordered_map<uint32_t, ElectPoolPtr> elect_pool_map_;
    std::mutex elect_pool_map_mutex_;
    // one ip just one node
    std::unordered_set<uint32_t> node_ip_set_;
    std::mutex node_ip_set_mutex_;
    std::unordered_map<std::string, NodeDetailPtr> all_node_map_;
    std::mutex all_node_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ElectPoolManager);
};

};  // namespace elect

};  //  namespace tenon
