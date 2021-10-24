#pragma once

#include <random>
#include <map>

#include "bft/proto/bft.pb.h"
#include "block/proto/block.pb.h"
#include "common/bitmap.h"
#include "election/elect_pool.h"
#include "election/proto/elect.pb.h"
#include "election/elect_waiting_nodes.h"

namespace tenon {

namespace elect {

class ElectPoolManager {
public:
    ElectPoolManager();
    ~ElectPoolManager();
    void NetworkMemberChange(uint32_t network_id, MembersPtr& members_ptr);
    void AddWaitingPoolNode(uint32_t network_id, NodeDetailPtr& node_ptr);
    void UpdateNodeInfoWithBlock(const bft::protobuf::Block& block_info);
    int BackupCheckElectionBlockTx(
        const bft::protobuf::TxInfo& local_tx_info,
        const bft::protobuf::TxInfo& tx_info);
    void UpdateWaitingNodes(
        uint32_t waiting_shard_id,
        const std::string& root_node_id,
        const common::BloomFilter& nodes_filter);
    int CreateElectTransaction(
        uint32_t shard_netid,
        uint64_t final_statistic_block_height,
        const bft::protobuf::TxInfo& src_tx_info,
        bft::protobuf::TxInfo& tx_info);
    void OnTimeBlock(uint64_t tm_block_tm);
    int GetElectionTxInfo(bft::protobuf::TxInfo& tx_info);

private:
    int GetAllTxInfoBloomFiler(
        const bft::protobuf::TxInfo& tx_info,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        elect::protobuf::ElectBlock* ec_block);
    int GetAllBloomFilerAndNodes(
        const block::protobuf::StatisticInfo& statistic_info,
        uint32_t shard_netid,
        common::BloomFilter* cons_all,
        common::BloomFilter* cons_weed_out,
        common::BloomFilter* pick_all,
        common::BloomFilter* pick_in,
        std::vector<NodeDetailPtr>& exists_shard_nodes,
        std::vector<NodeDetailPtr>& weed_out_vec,
        std::vector<NodeDetailPtr>& pick_in_vec,
        int32_t* leader_count);
    void FtsGetNodes(
        bool weed_out,
        uint32_t count,
        common::BloomFilter* nodes_filter,
        const std::vector<NodeDetailPtr>& src_nodes,
        std::vector<NodeDetailPtr>& res_nodes);
    void SmoothFtsValue(
        int32_t count,
        std::mt19937_64& g2,
        std::vector<NodeDetailPtr>& src_nodes);
    void GetMiniTopNInvalidNodes(
        uint32_t network_id,
        const block::protobuf::StatisticInfo& statistic_info,
        uint32_t count,
        std::map<std::string, uint32_t>* nodes);
    int SelectLeader(uint32_t network_id, const common::Bitmap& bitmap, elect::protobuf::ElectBlock* ec_block);

    std::unordered_map<uint32_t, ElectPoolPtr> elect_pool_map_;
    std::mutex elect_pool_map_mutex_;
    // one ip just one node
    std::unordered_set<uint32_t> node_ip_set_;
    std::mutex node_ip_set_mutex_;
    std::unordered_map<std::string, NodeDetailPtr> all_node_map_;
    std::mutex all_node_map_mutex_;
    std::unordered_map<uint32_t, ElectWaitingNodesPtr> waiting_pool_map_;
    std::mutex waiting_pool_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ElectPoolManager);
};

};  // namespace elect

};  //  namespace tenon
