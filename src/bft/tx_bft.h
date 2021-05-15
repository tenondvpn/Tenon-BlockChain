#pragma once

#include <string>

#include "bft/bft_interface.h"
#include "bft/proto/bft.pb.h"
#include "bft/proto/bft_proto.h"

namespace lego {

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
    int CheckTxInfo(const protobuf::Block& block_info, const protobuf::TxInfo& tx_info);
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

    DISALLOW_COPY_AND_ASSIGN(TxBft);
};

}  // namespace bft

}  //namespace lego
