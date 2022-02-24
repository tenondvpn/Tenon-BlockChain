#pragma once

#include <string>

#include "bft/bft_interface.h"
#include "bft/proto/bft.pb.h"
#include "bft/proto/bft_proto.h"

namespace tenon {

namespace tvm {
    class TenonHost;
}

namespace bft {

class TxBft : public BftInterface {
public:
    TxBft();
    virtual ~TxBft();
    virtual int Init();
    virtual int Prepare(
        bool leader,
        int32_t pool_mod_idx,
        const bft::protobuf::BftMessage& leaser_bft_msg,
        std::string* prepare);
    virtual int PreCommit(bool leader, std::string& pre_commit);
    virtual int Commit(bool leader, std::string& commit);

private:
    int LeaderCreatePrepare(int32_t pool_mod_idx, std::string* bft_str);
    int BackupCheckPrepare(
        const bft::protobuf::BftMessage& bft_msg,
        int32_t* invalid_tx_idx,
        std::string* prepare);
    int LeaderCreatePreCommit(std::string& bft_str);
    int LeaderCreateCommit(std::string& bft_str);
    int CheckBlockInfo(const protobuf::Block& block_info);
    int CheckTxInfo(
        const protobuf::Block& block_info,
        const protobuf::TxInfo& tx_info,
        TxItemPtr local_tx);
    void DoTransactionAndCreateTxBlock(
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    void RootDoTransactionAndCreateTxBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    void RootLeaderCreateAccountAddressBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    void RootLeaderCreateElectConsensusShardBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    void RootLeaderCreateTimerBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    void RootLeaderCreateFinalStatistic(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    int RootBackupCheckPrepare(
        const bft::protobuf::BftMessage& bft_msg,
        int32_t* invalid_tx_idx,
        std::string* prepare);
    int RootBackupCheckCreateAccountAddressPrepare(
        const bft::protobuf::Block& block,
        int32_t* invalid_tx_idx);
    int RootBackupCheckElectConsensusShardPrepare(const bft::protobuf::Block& block);
    int RootBackupCheckTimerBlockPrepare(const bft::protobuf::Block& block);
    int RootBackupCheckFinalStatistic(const bft::protobuf::Block& block);
    int GetTempAccountBalance(
        const std::string& id,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        uint64_t* balance);
    int CallContract(
        TxItemPtr tx_info,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res);
    int LeaderAddNormalTransaction(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int LeaderAddCallContract(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int LeaderCallContractDefault(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int LeaderCallContractExceute(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int LeaderCallContractCalled(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int CreateContractCallExcute(
        TxItemPtr tx_info,
        uint64_t gas_limit,
        const std::string& bytes_code,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res);
    int BackupNormalCheck(
        TxItemPtr local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, bool>& locked_account_map,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckContractDefault(
        TxItemPtr local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, bool>& locked_account_map,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckContractExceute(
        TxItemPtr local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckContractCalled(
        TxItemPtr local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckFinalStatistic(
        TxItemPtr local_tx_ptr,
        const protobuf::TxInfo& tx_info);
    int GetTimeBlockInfoFromTx(const protobuf::TxInfo& tx_info, uint64_t* tm_height, uint64_t* tm);
    std::shared_ptr<bft::protobuf::TbftLeaderPrepare> CreatePrepareTxInfo(
        std::shared_ptr<bft::protobuf::Block>& block_ptr,
        bft::protobuf::LeaderTxPrepare& ltx_prepare);
    int DoTransaction(
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg);
    void LeaderCallTransaction(std::vector<TxItemPtr>& tx_vec);

    DISALLOW_COPY_AND_ASSIGN(TxBft);
};

}  // namespace bft

}  //namespace tenon
