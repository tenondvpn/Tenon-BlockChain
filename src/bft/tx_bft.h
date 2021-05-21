#pragma once

#include <string>

#include "bft/bft_interface.h"
#include "bft/proto/bft.pb.h"
#include "bft/proto/bft_proto.h"
#include "evmc/evmc.hpp"

namespace tenon {

namespace tvm {
    class TenonHost;
}

namespace bft {

class TxBft : public BftInterface {
public:
    TxBft();
    virtual ~TxBft();
    virtual int Init(bool leader);
    virtual int Prepare(bool leader, std::string& prepare);
    virtual int PreCommit(bool leader, std::string& pre_commit);
    virtual int Commit(bool leader, std::string& commit);

private:
    int LeaderCreatePrepare(std::string& bft_str);
    int BackupCheckPrepare(std::string& bft_str);
    int LeaderCreatePreCommit(std::string& bft_str);
    int LeaderCreateCommit(std::string& bft_str);
    int CheckBlockInfo(const protobuf::Block& block_info);
    int CheckTxInfo(
        const protobuf::Block& block_info,
        const protobuf::TxInfo& tx_info,
        TxItemPtr* local_tx);
    void LeaderCreateTxBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& bft_msg);
    void RootLeaderCreateNewAccountTxBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& bft_msg);
    int RootBackupCheckPrepare(std::string& bft_str);
    int GetTempAccountBalance(
        const std::string& id,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        uint64_t* balance);
    int CallContract(
        const TxItemPtr& tx_info,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res);
    int LeaderAddNormalTransaction(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int LeaderAddCallContract(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int LeaderCallContractDefault(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int LeaderCallContractLock(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx);
    int LeaderCheckCallContract(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int LeaderAddContractCalled(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx);
    int CreateContractCallExcute(
        const TxItemPtr& tx_info,
        uint64_t gas_limit,
        const std::string& bytes_code,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res);
    int BackupNormalCheck(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckContractDefault(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckContractInited(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map);
    int BackupCheckContractLocked(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map);
    int BackupCheckContractCalled(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map);


    DISALLOW_COPY_AND_ASSIGN(TxBft);
};

}  // namespace bft

}  //namespace tenon
