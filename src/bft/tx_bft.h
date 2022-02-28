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
    int CheckBlockInfo(const protobuf::Block& block_info);
    int CheckTxInfo(
        const protobuf::Block& block_info,
        const protobuf::TxInfo& tx_info,
        TxItemPtr local_tx);
    void DoTransactionAndCreateTxBlock(
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block);
    void RootDoTransactionAndCreateTxBlock(
        uint32_t pool_idx,
        uint64_t pool_height,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block);
    void RootCreateAccountAddressBlock(
        uint32_t pool_idx,
        int64_t pool_height,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block);
    void RootCreateElectConsensusShardBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block);
    void RootCreateTimerBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block);
    void RootCreateFinalStatistic(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::Block& tenon_block);
    int RootBackupCheckPrepare(
        const bft::protobuf::BftMessage& bft_msg,
        int32_t* invalid_tx_idx,
        std::string* prepare);
    int GetTempAccountBalance(
        const std::string& id,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        uint64_t* balance);
    int CallContract(
        TxItemPtr tx_info,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res);
    int AddNormalTransaction(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int AddCallContract(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int CallContractDefault(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int CallContractExceute(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int CallContractCalled(
        TxItemPtr tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int CreateContractCallExcute(
        TxItemPtr tx_info,
        uint64_t gas_limit,
        const std::string& bytes_code,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res);
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
