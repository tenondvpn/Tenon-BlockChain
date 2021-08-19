#pragma once

#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "common/tick.h"
#include "common/limit_hash_map.h"
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
    int AddKeyValueSyncBlock(
        const transport::protobuf::Header& header,
        std::shared_ptr<bft::protobuf::Block>& block_ptr);

private:
    BftManager();
    ~BftManager();
    void HandleMessage(const transport::TransportMessagePtr& header);
    int InitBft(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void RemoveBft(const std::string& gid, bool remove_tx);
    int LeaderPrepare(BftInterfacePtr& bft_ptr, int32_t pool_mod_idx);
    int BackupPrepare(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int LeaderPrecommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int BackupPrecommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        const std::string& sign_hash,
        bft::protobuf::BftMessage& bft_msg);
    int LeaderCommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int BackupCommit(
        BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void CheckTimeout();
    int VerifySignature(
        const elect::BftMemberPtr& mem_ptr,
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& sha128,
        security::Signature& sign);
//     int VerifyBlockSignature(
//         uint32_t mem_index,
//         const bft::protobuf::BftMessage& bft_msg,
//         const bft::protobuf::Block& tx_block,
//         security::Signature& sign);
    int VerifySignatureWithBftMessage(
        const bft::protobuf::BftMessage& bft_msg,
        std::string* tx_hash);
    int VerifyLeaderSignature(
        const elect::BftMemberPtr& mem_ptr,
        const bft::protobuf::BftMessage& bft_msg,
        std::string* sign_hash);
    int VerifyBlsAggSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg,
        const std::string& sign_hash);
    void LeaderBroadcastToAcc(BftInterfacePtr& bft_ptr, bool is_bft_leader);
    void HandleToAccountTxBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void HandleRootTxBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void HandleSyncBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    int CreateGenisisBlock(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    bool AggSignValid(uint32_t thread_idx, uint32_t type, const bft::protobuf::Block& block);
    void RootCommitAddNewAccount(const bft::protobuf::Block& block, db::DbWriteBach& db_batch);
    int LeaderCallPrecommit(BftInterfacePtr& bft_ptr);
    int LeaderCallCommit(const transport::protobuf::Header& header, BftInterfacePtr& bft_ptr);
    void HandleOpposeNodeMsg(bft::protobuf::BftMessage& bft_msg, BftInterfacePtr& bft_ptr);
    BftInterfacePtr CreateBftPtr(const bft::protobuf::BftMessage& bft_msg);
    void HandleBftMessage(
        BftInterfacePtr& bft_ptr,
        bft::protobuf::BftMessage& bft_msg,
        const std::string& sign_hash,
        const transport::TransportMessagePtr& header_ptr);
    void BackupPrepareOppose(
        const transport::protobuf::Header& header,
        BftInterfacePtr& bft_ptr,
        bft::protobuf::BftMessage& bft_msg,
        const std::string& res_data);
    int LeaderCallPrecommitOppose(const BftInterfacePtr& bft_ptr);
    int LeaderCallCommitOppose(const transport::protobuf::Header& header, BftInterfacePtr& bft_ptr);
    void BlockToDb();
    void VerifyWaitingBlock();
    bool VerifyAggSignWithMembers(
        const elect::MembersPtr& members,
        const bft::protobuf::Block& block);
    void HandleVerifiedBlock(
        uint32_t thread_idx,
        uint32_t type,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr);
    void HandleSyncWaitingBlock(
        uint32_t thread_idx,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr);
    void HandleToWaitingBlock(
        uint32_t thread_idx,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr);
    void HandleRootWaitingBlock(
        uint32_t thread_idx,
        const bft::protobuf::Block& block,
        BlockPtr& block_ptr);
    void BackupSendOppose(
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void LeaderHandleBftOppose(
        const BftInterfacePtr& bft_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void BackupHandleBftOppose(
        const elect::BftMemberPtr& mem_ptr,
        const transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg);
    void BackupHandleBftMessage(BftItemPtr& bft_item_ptr);
    void SetBftGidPrepareInvalid(BftItemPtr& bft_item_ptr);
    void CacheBftPrecommitMsg(BftItemPtr& bft_item_ptr);

    static const uint32_t kBlockToDbPeriod = 10000llu;

    std::unordered_map<std::string, BftInterfacePtr> bft_hash_map_;
    std::mutex bft_hash_map_mutex_;
    common::Tick timeout_tick_;
    std::atomic<uint32_t> tps_{ 0 };
    std::atomic<uint32_t> pre_tps_{ 0 };
    uint64_t tps_btime_{ 0 };
    BlockQueue block_queue_[transport::kMessageHandlerThreadCount];
    common::Tick block_to_db_tick_;
    WaitingBlockQueue waiting_verify_block_queue_[transport::kMessageHandlerThreadCount];
    common::Tick verify_block_tick_;
    std::unordered_set<WaitingBlockItemPtr> waiting_block_set_;
    common::Tick leader_resend_tick_;
    common::LimitHashMap<std::string, BftItemPtr> bft_gid_map_{ 102400 };
    std::mutex bft_gid_map_mutex_;

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
