#pragma once

#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "common/tick.h"
#include "db/db.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "election/member_manager.h"
#include "bft/bft_interface.h"
#include "election/proto/elect.pb.h"
#include "bft/proto/bft.pb.h"

namespace tenon {

namespace bft {

class BftManager {
public:
    static BftManager* Instance();
    // load bft code by bft addr
    int StartBft(const std::string& gid, int32_t pool_mod_index);
    int AddBft(BftInterfacePtr& bft_ptr);
    BftInterfacePtr GetBft(const std::string& gid);
    uint32_t GetMemberIndex(uint32_t network_id, const std::string& node_id);
    elect::MembersPtr GetNetworkMembers(uint32_t network_id);
    int AddGenisisBlock(const std::shared_ptr<bft::protobuf::Block>& genesis_block);

private:
    BftManager();
    ~BftManager();
    void HandleMessage(transport::TransportMessagePtr& header);
    int InitBft(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void RemoveBft(const std::string& gid, bool remove_tx);
    int LeaderPrepare(BftInterfacePtr& bft_ptr, int32_t pool_mod_idx);
    int BackupPrepare(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int LeaderPrecommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int BackupPrecommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int LeaderCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int BackupCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void CheckTimeout();
    int VerifySignature(
        uint32_t mem_index,
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& sha128,
        security::Signature& sign);
    int VerifyBlockSignature(
        uint32_t mem_index,
        const bft::protobuf::BftMessage& bft_msg,
        const bft::protobuf::Block& tx_block,
        security::Signature& sign);
    int VerifySignatureWithBftMessage(
        const bft::protobuf::BftMessage& bft_msg,
        std::string* tx_hash);
    int VerifyLeaderSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg);
    int VerifyAggSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg);
    void LeaderBroadcastToAcc(BftInterfacePtr& bft_ptr, bool is_bft_leader);
    void HandleToAccountTxBlock(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void HandleRootTxBlock(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void HandleSyncBlock(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int CreateGenisisBlock(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    bool AggSignValid(const bft::protobuf::Block& block);
    void RootCommitAddNewAccount(const bft::protobuf::Block& block, db::DbWriteBach& db_batch);
    int LeaderCallPrecommit(BftInterfacePtr& bft_ptr);
    int LeaderCallCommit(BftInterfacePtr& bft_ptr);
    int LeaderReChallenge(BftInterfacePtr& bft_ptr);
    void HandleOpposeNodeMsg(bft::protobuf::BftMessage& bft_msg, BftInterfacePtr& bft_ptr);
    BftInterfacePtr CreateBftPtr(const bft::protobuf::BftMessage& bft_msg);
    void HandleBftMessage(
        BftInterfacePtr& bft_ptr,
        bft::protobuf::BftMessage& bft_msg,
        transport::TransportMessagePtr& header_ptr);

    std::unordered_map<std::string, BftInterfacePtr> bft_hash_map_;
    std::mutex bft_hash_map_mutex_;
    common::Tick timeout_tick_;
    std::atomic<uint32_t> tps_{ 0 };
    std::atomic<uint32_t> pre_tps_{ 0 };
    uint64_t tps_btime_{ 0 };
    std::mutex all_test_mutex_;
    std::unordered_set<std::string> block_hash_added_;
    std::mutex block_hash_added_mutex_;

#ifdef TENON_UNITTEST
    // just for test
    transport::protobuf::Header leader_prepare_msg_;
    transport::protobuf::Header backup_prepare_msg_;
    transport::protobuf::Header leader_precommit_msg_;
    transport::protobuf::Header backup_precommit_msg_;
    transport::protobuf::Header leader_commit_msg_;
    transport::protobuf::Header root_leader_broadcast_msg_;
    transport::protobuf::Header to_leader_broadcast_msg_;
#endif

    DISALLOW_COPY_AND_ASSIGN(BftManager);
};

}  // namespace bft

}  // namespace tenon
