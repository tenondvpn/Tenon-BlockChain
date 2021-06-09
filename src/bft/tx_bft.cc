#include "stdafx.h"
#include "bft/tx_bft.h"

#include "common/global_info.h"
#include "common/random.h"
#include "contract/contract_manager.h"
#include "contract/contract_utils.h"
#include "block/account_manager.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "sync/key_value_sync.h"
#include "security/secp256k1.h"
#include "tvm/execution.h"
#include "tvm/tvm_utils.h"
#include "tvm/tenon_host.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/dispatch_pool.h"
#include "bft/gid_manager.h"
#include "timeblock/time_block_manager.h"
#include "timeblock/time_block_utils.h"

namespace tenon {

namespace bft {

TxBft::TxBft() {}

TxBft::~TxBft() {}

int TxBft::Init(bool leader) {
//     std::vector<TxItemPtr> tx_vec;
//     uint32_t pool_index = 0;
//     DispatchPool::Instance()->GetTx(pool_index, tx_vec);
//     if (tx_vec.empty()) {
//         return kBftNoNewTxs;
//     }

    return kBftSuccess;
}

int TxBft::Prepare(bool leader, int32_t pool_mod_idx, std::string& prepare) {
    if (leader) {
        return LeaderCreatePrepare(pool_mod_idx, prepare);
    }

    bft::protobuf::BftMessage bft_msg;
    if (!bft_msg.ParseFromString(prepare)) {
        BFT_ERROR("bft::protobuf::BftMessage ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!bft_msg.has_data()) {
        BFT_ERROR("bft::protobuf::BftMessage has no data!");
        return kBftInvalidPackage;
    }

    // TODO: check leader valid

    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (RootBackupCheckPrepare(bft_msg) != kBftSuccess) {
            return kBftError;
        }
    } else {
        if (BackupCheckPrepare(bft_msg) != kBftSuccess) {
            return kBftError;
        }
    }

    prepare = "";
    return kBftSuccess;
}

int TxBft::PreCommit(bool leader, std::string& pre_commit) {
    if (leader) {
        LeaderCreatePreCommit(pre_commit);
        return kBftSuccess;
    }

    pre_commit = "";
    return kBftSuccess;
}

int TxBft::Commit(bool leader, std::string& commit) {
    if (leader) {
        LeaderCreateCommit(commit);
        return kBftSuccess;
    }
    commit = "";
    return kBftSuccess;
}

int TxBft::LeaderCreatePrepare(int32_t pool_mod_idx, std::string& bft_str) {
    uint32_t pool_index = 0;
    std::vector<TxItemPtr> tx_vec;
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        auto tx_ptr = DispatchPool::Instance()->GetRootTx();
        if (tx_ptr != nullptr) {
            pool_index = common::kRootChainPoolIndex;
            tx_vec.push_back(tx_ptr);
        }
    }

    if (tx_vec.empty()) {
        DispatchPool::Instance()->GetTx(pool_index, pool_mod_idx, tx_vec);
        if (tx_vec.empty()) {
            BFT_ERROR("get tx error, empty.");
            return kBftNoNewTxs;
        }
    }

    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        add_item_index_vec(tx_vec[i]->index);
        push_bft_item_vec(tx_vec[i]->tx.gid());
    }

    set_pool_index(pool_index);
    bft::protobuf::TxBft tx_bft;
    auto& ltx_prepare = *(tx_bft.mutable_ltx_prepare());
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        RootLeaderCreateTxBlock(pool_index, tx_vec, ltx_prepare);
    } else {
        LeaderCreateTxBlock(tx_vec, ltx_prepare);
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(ltx_prepare.block());
    SetBlock(block_ptr);
    bft_str = tx_bft.SerializeAsString();
    set_prepare_hash(ltx_prepare.block().hash());
    return kBftSuccess;
}

int TxBft::RootBackupCheckCreateAccountAddressPrepare(const bft::protobuf::Block& block) {
    std::unordered_map<std::string, int64_t> acc_balance_map;
    for (int32_t i = 0; i < block.tx_list_size(); ++i) {
        const auto& tx_info = block.tx_list(i);
        if (!tx_info.to_add()) {
            BFT_ERROR("must transfer to new account.");
            return kBftError;
        }

        auto local_tx_info = DispatchPool::Instance()->GetTx(
            pool_index(),
            tx_info.to_add(),
            tx_info.type(),
            tx_info.call_contract_step(),
            tx_info.gid());
        if (local_tx_info == nullptr) {
            BFT_ERROR("prepare [to: %d] [pool idx: %d] not has tx[%s]to[%s][%s]!",
                tx_info.to_add(),
                pool_index(),
                common::Encode::HexEncode(tx_info.from()).c_str(),
                common::Encode::HexEncode(tx_info.to()).c_str(),
                common::Encode::HexEncode(tx_info.gid()).c_str());
            return kBftTxNotExists;
        }

        if (local_tx_info->tx.amount() != tx_info.amount()) {
            BFT_ERROR("local amount is not equal leader amount.");
            return kBftError;
        }

        if (local_tx_info->tx.to() != tx_info.to()) {
            BFT_ERROR("local to is not equal leader to.");
            return kBftError;
        }

        if (local_tx_info->tx.gas_limit() != tx_info.gas_limit()) {
            BFT_ERROR("local gas_limit is not equal leader gas_limit.");
            return kBftError;
        }

        if (local_tx_info->tx.balance() != tx_info.balance()) {
            BFT_ERROR("local balance is not equal leader balance.");
            return kBftError;
        }

        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx_info.to());
        if (acc_info != nullptr) {
            BFT_ERROR("account exists now.");
            return kBftError;
        }

        if (local_tx_info->tx.type() != tx_info.type()) {
            BFT_ERROR("local tx type[%d] not eq to leader[%d].",
                local_tx_info->tx.type(), tx_info.type());
            return kBftError;
        }

        if (local_tx_info->tx.type() == common::kConsensusCreateContract) {
                uint32_t network_id = 0;
                if (block::AccountManager::Instance()->GetAddressConsensusNetworkId(
                        local_tx_info->tx.from(),
                        &network_id) != block::kBlockSuccess) {
                    BFT_ERROR("get network_id error!");
                    continue;
                }

                if (network_id != tx_info.network_id()) {
                    return kBftError;
                }
        } else {
            if (tx_info.network_id() != NewAccountGetNetworkId(tx_info.to())) {
                BFT_ERROR("leader set network id not equal to local[%u][%u].",
                    tx_info.network_id(), NewAccountGetNetworkId(tx_info.to()));
                return kBftError;
            }
        }

        push_bft_item_vec(tx_info.gid());
    }

    auto block_hash = GetBlockHash(block);
    if (block_hash != block.hash()) {
        BFT_ERROR("block hash error!");
        return kBftError;
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
    SetBlock(block_ptr);
    return kBftSuccess;
}

int TxBft::RootBackupCheckTimerBlockPrepare(const bft::protobuf::Block& block) {
    std::unordered_map<std::string, int64_t> acc_balance_map;
    int32_t i = 0;
    const auto& tx_info = block.tx_list(i);
    auto local_tx_info = DispatchPool::Instance()->GetTx(
        pool_index(),
        tx_info.to_add(),
        tx_info.type(),
        tx_info.call_contract_step(),
        tx_info.gid());
    if (local_tx_info == nullptr) {
        BFT_ERROR("prepare [to: %d] [pool idx: %d] not has tx[%s]to[%s][%s]!",
            tx_info.to_add(),
            pool_index(),
            common::Encode::HexEncode(tx_info.from()).c_str(),
            common::Encode::HexEncode(tx_info.to()).c_str(),
            common::Encode::HexEncode(tx_info.gid()).c_str());
        return kBftTxNotExists;
    }

    if (local_tx_info->tx.amount() != tx_info.amount()) {
        BFT_ERROR("local amount is not equal leader amount.");
        return kBftError;
    }

    if (local_tx_info->tx.to() != tx_info.to()) {
        BFT_ERROR("local to is not equal leader to.");
        return kBftError;
    }

    if (local_tx_info->tx.gas_limit() != tx_info.gas_limit()) {
        BFT_ERROR("local gas_limit is not equal leader gas_limit.");
        return kBftError;
    }

    if (local_tx_info->tx.balance() != tx_info.balance()) {
        BFT_ERROR("local balance is not equal leader balance.");
        return kBftError;
    }

    if (local_tx_info->tx.type() != tx_info.type() ||
            tx_info.type() != common::kConsensusRootTimeBlock) {
        BFT_ERROR("local tx type[%d] not eq to leader[%d].",
            local_tx_info->tx.type(), tx_info.type());
        return kBftError;
    }

    if (tmblock::TimeBlockManager::Instance()->BackupCheckTimeBlockTx(
            tx_info) != tmblock::kTimeBlockSuccess) {
        BFT_ERROR("BackupCheckTimeBlockTx error.");
        return kBftError;
    }

    push_bft_item_vec(tx_info.gid());
    auto block_hash = GetBlockHash(block);
    if (block_hash != block.hash()) {
        BFT_ERROR("block hash error!");
        return kBftError;
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
    SetBlock(block_ptr);
    return kBftSuccess;
}

int TxBft::RootBackupCheckElectConsensusShardPrepare(const bft::protobuf::Block& block) {
    std::unordered_map<std::string, int64_t> acc_balance_map;
    int32_t i = 0;
    const auto& tx_info = block.tx_list(i);
    auto local_tx_info = DispatchPool::Instance()->GetTx(
        pool_index(),
        tx_info.to_add(),
        tx_info.type(),
        tx_info.call_contract_step(),
        tx_info.gid());
    if (local_tx_info == nullptr) {
        BFT_ERROR("prepare [to: %d] [pool idx: %d] not has tx[%s]to[%s][%s]!",
            tx_info.to_add(),
            pool_index(),
            common::Encode::HexEncode(tx_info.from()).c_str(),
            common::Encode::HexEncode(tx_info.to()).c_str(),
            common::Encode::HexEncode(tx_info.gid()).c_str());
        return kBftTxNotExists;
    }

    if (local_tx_info->tx.amount() != tx_info.amount()) {
        BFT_ERROR("local amount is not equal leader amount.");
        return kBftError;
    }

    if (local_tx_info->tx.to() != tx_info.to()) {
        BFT_ERROR("local to is not equal leader to.");
        return kBftError;
    }

    if (local_tx_info->tx.gas_limit() != tx_info.gas_limit()) {
        BFT_ERROR("local gas_limit is not equal leader gas_limit.");
        return kBftError;
    }

    if (local_tx_info->tx.balance() != tx_info.balance()) {
        BFT_ERROR("local balance is not equal leader balance.");
        return kBftError;
    }

    if (local_tx_info->tx.type() != tx_info.type() ||
            tx_info.type() != common::kConsensusRootElectShard) {
        BFT_ERROR("local tx type[%d] not eq to leader[%d].",
            local_tx_info->tx.type(), tx_info.type());
        return kBftError;
    }

    if (elect::ElectManager::Instance()->BackupCheckElectConsensusShard(
            tx_info) != elect::kElectSuccess) {
        return kBftError;
    }

    push_bft_item_vec(tx_info.gid());
    auto block_hash = GetBlockHash(block);
    if (block_hash != block.hash()) {
        BFT_ERROR("block hash error!");
        return kBftError;
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
    SetBlock(block_ptr);
    return kBftSuccess;
}

int TxBft::RootBackupCheckPrepare(const bft::protobuf::BftMessage& bft_msg) {
    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("bft::protobuf::TxBft ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!tx_bft.ltx_prepare().has_block()) {
        BFT_ERROR("prepare has no transaction!");
        return kBftInvalidPackage;
    }

    const auto& block = tx_bft.ltx_prepare().block();
    int res = CheckBlockInfo(block);
    if (res != kBftSuccess) {
        BFT_ERROR("bft check block info failed[%d]", res);
        return res;
    }

    if (block.tx_list_size() == 1) {
        switch (block.tx_list(0).type())
        {
        case common::kConsensusRootElectRoot:
            break;
        case common::kConsensusRootElectShard:
            return RootBackupCheckElectConsensusShardPrepare(block);
            break;
        case common::kConsensusRootTimeBlock:
            return RootBackupCheckTimerBlockPrepare(block);
            break;
        case common::kConsensusRootVssBlock:
            break;
        default:
            return RootBackupCheckCreateAccountAddressPrepare(block);
            break;
        }
    } else {
        return RootBackupCheckCreateAccountAddressPrepare(block);
    }
    
    return kBftInvalidPackage;
}

int TxBft::BackupCheckPrepare(const bft::protobuf::BftMessage& bft_msg) {
    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("bft::protobuf::TxBft ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!tx_bft.ltx_prepare().has_block()) {
        BFT_ERROR("prepare has no transaction!");
        return kBftInvalidPackage;
    }

    const auto& block = tx_bft.ltx_prepare().block();
    int res = CheckBlockInfo(block);
    if (res != kBftSuccess) {
        BFT_ERROR("bft check block info failed[%d]", res);
        return res;
    }

    std::unordered_map<std::string, int64_t> acc_balance_map;
    std::unordered_map<std::string, bool> locked_account_map;
    for (int32_t i = 0; i < block.tx_list_size(); ++i) {
        const auto& tx_info = block.tx_list(i);
        TxItemPtr local_tx_info = nullptr;
        int tmp_res = CheckTxInfo(block, tx_info, &local_tx_info);
        if (tmp_res != kBftSuccess || local_tx_info == nullptr) {
            BFT_ERROR("check transaction failed![%d]", tmp_res);
            return tmp_res;
        }

        if (local_tx_info->tx.type() != common::kConsensusCallContract &&
                local_tx_info->tx.type() != common::kConsensusCreateContract) {
            int check_res = BackupNormalCheck(
                local_tx_info,
                tx_info,
                locked_account_map,
                acc_balance_map);
            if (check_res != kBftSuccess) {
                BFT_ERROR("BackupNormalCheck failed!");
                return check_res;
            }
        } else {
            switch (local_tx_info->tx.call_contract_step()) {
            case contract::kCallStepDefault: {
                int check_res = BackupCheckContractDefault(
                    local_tx_info,
                    tx_info,
                    locked_account_map,
                    acc_balance_map);
                if (check_res != kBftSuccess) {
                    BFT_ERROR("BackupCheckContractDefault transaction failed![%d]", tmp_res);
                    return check_res;
                }
                break;
            }
            case contract::kCallStepCallerInited: {
                int check_res = BackupCheckContractExceute(local_tx_info, tx_info, acc_balance_map);
                if (check_res != kBftSuccess) {
                    BFT_ERROR("BackupCheckContractExceute transaction failed![%d]", tmp_res);
                    return check_res;
                }
                break;
            }
            case contract::kCallStepContractCalled: {
                int check_res = BackupCheckContractCalled(local_tx_info, tx_info, acc_balance_map);
                if (check_res != kBftSuccess) {
                    BFT_ERROR("BackupCheckContractCalled transaction failed![%d]", tmp_res);
                    return check_res;
                }
                break;
            }
            default:
                return kBftInvalidPackage;
            }
        }
    }

    auto block_hash = GetBlockHash(block);
    if (block_hash != block.hash()) {
        BFT_ERROR("block hash error!");
        return kBftError;
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
    SetBlock(block_ptr);
    return kBftSuccess;
}

int TxBft::BackupCheckContractDefault(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, bool>& locked_account_map,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(local_tx_ptr->tx.from());
    if (account_info->locked()) {
        locked_account_map[local_tx_ptr->tx.from()] = true;
        return kBftError;
    }

    if (tx_info.gas_price() != common::GlobalInfo::Instance()->gas_price()) {
        BFT_ERROR("leader gas pirce[%lu] ne local[%lu]",
            tx_info.gas_price(), common::GlobalInfo::Instance()->gas_price());
        return kBftLeaderInfoInvalid;
    }

    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    int backup_status = kBftSuccess;
    uint64_t gas_used = 0;
    do
    {
        if (locked_account_map.find(local_tx_ptr->tx.from()) != locked_account_map.end()) {
            if (tx_info.status() != kBftContractAddressLocked) {
                BFT_ERROR("backup account locked error.");
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
            break;
        }

        int balance_status = GetTempAccountBalance(
            local_tx_ptr->tx.from(),
            acc_balance_map,
            &from_balance);
        if (balance_status != kBftSuccess) {
            if (tx_info.status() != (uint32_t)balance_status) {
                BFT_ERROR("get balace error.");
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
            break;
        }

        gas_used = kCallContractDefaultUseGas;
        if (!local_tx_ptr->attr_map.empty()) {
            for (auto iter = local_tx_ptr->attr_map.begin();
                    iter != local_tx_ptr->attr_map.end(); ++iter) {
                gas_used += (iter->first.size() + iter->second.size()) *
                    kKeyValueStorageEachBytes;
            }
        }

        if (from_balance < local_tx_ptr->tx.gas_limit() * tx_info.gas_price() ||
                from_balance <= (gas_used + kTransferGas) * tx_info.gas_price() ||
                local_tx_ptr->tx.gas_limit() < (gas_used + kTransferGas)) {
            if (tx_info.status() != kBftAccountBalanceError) {
                BFT_ERROR("gas limit error not eq[%d][%d].", tx_info.status(), kBftAccountBalanceError);
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
            break;
        }
    } while (0);
    
    if (from_balance >= gas_used * tx_info.gas_price()) {
        from_balance -= gas_used * tx_info.gas_price();
    } else {
        from_balance = 0;
        if (backup_status != kBftSuccess && tx_info.status() != kBftAccountBalanceError) {
            BFT_ERROR("gas limit error not eq[%d][%d].", tx_info.status(), kBftAccountBalanceError);
            return kBftLeaderInfoInvalid;
        }

        backup_status = tx_info.status();
    }

    if (tx_info.balance() != from_balance) {
        BFT_ERROR("balance error not eq[%lu][%lu].", tx_info.balance(), from_balance);
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.gas_used() != gas_used) {
        BFT_ERROR("gas_used error not eq[%lu][%lu].", tx_info.gas_used(), gas_used);
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.call_contract_step() != contract::kCallStepCallerInited) {
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.status() == kBftSuccess) {
        if (tx_info.gas_limit() != local_tx_ptr->tx.gas_limit() - gas_used) {
            BFT_ERROR("gas_limit error not eq[%lu][%lu].",
                tx_info.gas_limit(), local_tx_ptr->tx.gas_limit() - gas_used);
            return kBftLeaderInfoInvalid;
        }

        locked_account_map[local_tx_ptr->tx.from()] = true;
    }

    if (backup_status != (int)tx_info.status()) {
        return kBftLeaderInfoInvalid;
    }
    
    return kBftSuccess;
}

int TxBft::BackupCheckContractExceute(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    if (tx_info.gas_price() != common::GlobalInfo::Instance()->gas_price()) {
        return kBftLeaderInfoInvalid;
    }

    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t caller_balance = local_tx_ptr->tx.balance();
    uint64_t contract_balance = 0;
    auto local_tx_info = DispatchPool::Instance()->GetTx(
        pool_index(),
        local_tx_ptr->tx.to_add(),
        local_tx_ptr->tx.type(),
        local_tx_ptr->tx.call_contract_step(),
        local_tx_ptr->tx.gid());
    evmc_result evmc_res = {};
    evmc::result res{ evmc_res };
    tvm::TenonHost tenon_host;
    InitTenonTvmContext(tenon_host);
    int backup_status = kBftSuccess;
    do
    {
        int balance_status = GetTempAccountBalance(
            local_tx_ptr->tx.to(),
            acc_balance_map,
            &contract_balance);
        if (balance_status != kBftSuccess) {
            if (tx_info.status() != (uint32_t)balance_status) {
                BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
                    tx_info.status(), balance_status);
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
            break;
        }

        if (caller_balance < local_tx_ptr->tx.gas_limit() * tx_info.gas_price()) {
            if (tx_info.status() != kBftUserSetGasLimitError) {
                BFT_ERROR("caller_balance < local_tx_ptr->tx.gas_limit() * tx_info.gas_price()");
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
            break;
        }

        if (local_tx_ptr->tx.type() == common::kConsensusCallContract) {
            // will return from address's remove tenon and gas used
            tenon_host.AddTmpAccountBalance(
                local_tx_info->tx.from(),
                caller_balance);
            tenon_host.AddTmpAccountBalance(
                local_tx_info->tx.to(),
                contract_balance);
            int call_res = CallContract(local_tx_info, &tenon_host, &res);
            gas_used = local_tx_info->tx.gas_limit() - res.gas_left;
            if (call_res != kBftSuccess) {
                if (tx_info.status() != kBftExecuteContractFailed) {
                    BFT_ERROR("tx_info.status()[%d] != kBftExecuteContractFailed", tx_info.status());
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            if (res.status_code != EVMC_SUCCESS) {
                if (tx_info.status() != kBftExecuteContractFailed) {
                    BFT_ERROR("tx_info.status() != kBftExecuteContractFailed", tx_info.status());
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }
        } else {
            if (local_tx_ptr->attr_map.find(kContractBytesCode) == local_tx_ptr->attr_map.end()) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    BFT_ERROR("gas_limit error and status ne[%d][%d]!",
                        tx_info.status(), kBftCreateContractKeyError);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            if (security::Secp256k1::Instance()->GetContractAddress(
                    local_tx_ptr->tx.from(),
                    local_tx_ptr->tx.gid(),
                    local_tx_ptr->attr_map[kContractBytesCode]) != local_tx_ptr->tx.to()) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            tenon_host.AddTmpAccountBalance(
                local_tx_ptr->tx.from(),
                caller_balance);
            int call_res = CreateContractCallExcute(
                local_tx_ptr,
                local_tx_ptr->tx.gas_limit() - gas_used,
                local_tx_ptr->attr_map[kContractBytesCode],
                &tenon_host,
                &res);
            gas_used += local_tx_ptr->tx.gas_limit() - gas_used - res.gas_left;
            if (call_res != kBftSuccess) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    BFT_ERROR("gas_limit error and status ne[%d][%d]!",
                        tx_info.status(), kBftCreateContractKeyError);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            if (res.status_code != EVMC_SUCCESS) {
                if (tx_info.status() != kBftExecuteContractFailed) {
                    BFT_ERROR("kBftExecuteContractFailed error and status ne[%d][%d]!",
                        tx_info.status(), kBftExecuteContractFailed);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            if (gas_used >= local_tx_ptr->tx.gas_limit()) {
                if (tx_info.status() != kBftUserSetGasLimitError) {
                    BFT_ERROR("kBftUserSetGasLimitError error and status ne[%d][%d]!",
                        tx_info.status(), kBftUserSetGasLimitError);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            bool create_bytes_code_ok = false;
            for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
                if (tx_info.storages(i).id() == local_tx_ptr->tx.to() &&
                        tx_info.storages(i).key() == kContractCreatedBytesCode &&
                        tx_info.storages(i).value() == tenon_host.create_bytes_code_) {
                    create_bytes_code_ok = true;
                    break;
                }
            }

            if (!create_bytes_code_ok) {
                BFT_ERROR("gas_limit error and status ne[%d][%d]!",
                    tx_info.status(), kBftUserSetGasLimitError);
                return kBftLeaderInfoInvalid;
            }
        }
    } while (0);

    // use execute contract transfer amount to change from balance
    int64_t contract_balance_add = 0;
    int64_t caller_balance_add = 0;
    if (tx_info.status() == kBftSuccess) {
        uint32_t backup_storage_size = 0;
        for (auto account_iter = tenon_host.accounts_.begin();
                account_iter != tenon_host.accounts_.end(); ++account_iter) {
            for (auto storage_iter = account_iter->second.storage.begin();
                storage_iter != account_iter->second.storage.end(); ++storage_iter) {
                ++backup_storage_size;
            }
        }

        backup_storage_size += 2;  // add add_amount and gas_used
        if (tx_info.type() == common::kConsensusCreateContract) {
            backup_storage_size += 1;  // add contract kContractCreatedBytesCode
        }

        if (backup_storage_size != (uint32_t)tx_info.storages_size()) {
            BFT_ERROR("backup_storage_size[%u] != (uint32_t)tx_info.storages_size()[%d]",
                backup_storage_size, tx_info.storages_size());
            return kBftLeaderInfoInvalid;
        }

        // storage just caller can add
        for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
            if (tx_info.storages(i).key() == kContractCallerChangeAmount ||
                    tx_info.storages(i).key() == kContractCallerGasUsed ||
                    tx_info.storages(i).key() == kContractCreatedBytesCode) {
                continue;
            }

            evmc::address id;
            memcpy(id.bytes, tx_info.storages(i).id().c_str(), sizeof(id.bytes));
            auto account_iter = tenon_host.accounts_.find(id);
            if (account_iter == tenon_host.accounts_.end()) {
                BFT_ERROR("tx_info.storages(i).id()[%s] not exists",
                    common::Encode::HexEncode(tx_info.storages(i).id()).c_str());
                return kBftLeaderInfoInvalid;
            }

            evmc::bytes32 key;
            memcpy(key.bytes, tx_info.storages(i).key().c_str(), sizeof(key.bytes));
            auto iter = account_iter->second.storage.find(key);
            if (iter == account_iter->second.storage.end()) {
                BFT_ERROR("tx_info.storages(i).key() not exists",
                    common::Encode::HexEncode(tx_info.storages(i).key()));
                return kBftLeaderInfoInvalid;
            }

            std::string value((char*)iter->second.value.bytes, sizeof(iter->second.value.bytes));
            if (value != tx_info.storages(i).value()) {
                BFT_ERROR("tx_info.storages(i).value() not exists",
                    common::Encode::HexEncode(tx_info.storages(i).value()));
                return kBftLeaderInfoInvalid;
            }
        }

        auto& transfers = tenon_host.to_account_value_;
        if ((uint32_t)tx_info.transfers_size() != transfers.size()) {
            BFT_ERROR("tx_info.transfers_size() != transfers.size()");
            return kBftLeaderInfoInvalid;
        }

        for (int32_t i = 0; i < tx_info.transfers_size(); ++i) {
            auto iter = transfers.find(tx_info.transfers(i).from());
            if (iter == transfers.end()) {
                BFT_ERROR("transfers.find(tx_info.transfers(i).from()) failed");
                return kBftLeaderInfoInvalid;
            }

            auto to_iter = iter->second.find(tx_info.transfers(i).to());
            if (to_iter == iter->second.end()) {
                BFT_ERROR("iter->second.find(tx_info.transfers(i).to()) failed");
                return kBftLeaderInfoInvalid;
            }

            if (to_iter->second != to_iter->second) {
                BFT_ERROR("to_iter->second != to_iter->second");
                return kBftLeaderInfoInvalid;
            }

            if (tx_info.from() == iter->first) {
                caller_balance_add -= to_iter->second;
            }

            if (tx_info.from() == to_iter->first) {
                caller_balance_add += to_iter->second;
            }

            if (tx_info.to() == iter->first) {
                contract_balance_add -= to_iter->second;
            }

            if (tx_info.to() == to_iter->first) {
                contract_balance_add += to_iter->second;
            }
        }

        do 
        {
             if (((int64_t)caller_balance + caller_balance_add -
                 (int64_t)(local_tx_info->tx.amount())) >=
                 (int64_t)(gas_used * local_tx_info->tx.gas_price())) {
            } else {
                if (backup_status != kBftSuccess &&
                        tx_info.status() != kBftAccountBalanceError) {
                    BFT_ERROR("tx_info.balance() != 0");
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
             }

            if (tx_info.status() == kBftSuccess) {
                if (caller_balance_add < 0) {
                    if (caller_balance <
                            (uint64_t)(-caller_balance_add) + local_tx_info->tx.amount()) {
                        if (backup_status != kBftSuccess &&
                                tx_info.status() != kBftAccountBalanceError) {
                            BFT_ERROR("tx_info.status() == kBftAccountBalanceError");
                            return kBftLeaderInfoInvalid;
                        }

                        backup_status = tx_info.status();
                        break;
                    }
                }
            }

            if (tx_info.status() == kBftSuccess) {
                if (local_tx_info->tx.amount() > 0) {
                    if (caller_balance < local_tx_info->tx.amount()) {
                        if (backup_status != kBftSuccess &&
                                tx_info.status() != kBftAccountBalanceError) {
                            BFT_ERROR("tx_info.status() == kBftAccountBalanceError");
                            return kBftLeaderInfoInvalid;
                        }

                        backup_status = tx_info.status();
                        break;
                    }
                }
            }

            if (tx_info.status() == kBftSuccess) {
                if (contract_balance_add < 0) {
                    if (contract_balance < (uint64_t)(-contract_balance_add)) {
                        if (backup_status != kBftSuccess &&
                                tx_info.status() != kBftAccountBalanceError) {
                            BFT_ERROR("tx_info.status() == kBftAccountBalanceError");
                            return kBftLeaderInfoInvalid;
                        }

                        backup_status = tx_info.status();
                        break;
                    }
                    else {
                        contract_balance -= (uint64_t)(-contract_balance_add);
                    }
                } else {
                    contract_balance += contract_balance_add;
                }
            }
        } while (0);
    } else {
        if (caller_balance >= gas_used * tx_info.gas_price()) {
        } else {
            if (backup_status != kBftSuccess && tx_info.status() != kBftAccountBalanceError) {
                BFT_ERROR("tx_info.status() == kBftAccountBalanceError");
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
        }
    }

    bool caller_balance_valid = false;
    bool caller_gas_used_valid = false;
    for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
        if (tx_info.storages(i).key() == kContractCallerChangeAmount) {
            BFT_ERROR("caller_balance_add[%lu], tx_info.storages(i).value(): %s",
                caller_balance_add, tx_info.storages(i).value().c_str());
            if (caller_balance_add - (int64_t)(local_tx_info->tx.amount()) ==
                    common::StringUtil::ToInt64(tx_info.storages(i).value())) {
                caller_balance_valid = true;
            }
        }

        if (tx_info.storages(i).key() == kContractCallerGasUsed) {
            BFT_ERROR("gas_used[%lu], tx_info.storages(i).value(): %s",
                gas_used, tx_info.storages(i).value().c_str());
            if (gas_used == common::StringUtil::ToUint64(tx_info.storages(i).value())) {
                caller_gas_used_valid = true;
            }
        }
    }

    if (!caller_balance_valid || !caller_gas_used_valid) {
        BFT_ERROR("!caller_balance_valid || !caller_gas_used_valid");
        return kBftLeaderInfoInvalid;
    }

    contract_balance += local_tx_info->tx.amount();
    if (contract_balance != tx_info.balance()) {
        BFT_ERROR("contract_balance != tx_info.balance()");
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.gas_used() != 0) {
        BFT_ERROR("tx_info.gas_used() != 0");
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.call_contract_step() != contract::kCallStepContractCalled) {
        BFT_ERROR("tx_info.call_contract_step() != contract::kCallStepContractCalled");
        return kBftLeaderInfoInvalid;
    }

    if (backup_status != (int)tx_info.status()) {
        return kBftLeaderInfoInvalid;
    }

    acc_balance_map[local_tx_ptr->tx.from()] = contract_balance;
    return kBftSuccess;
}

int TxBft::BackupCheckContractCalled(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    // gas just consume by from
    uint64_t from_balance = 0;
    int64_t caller_balance_add = 0;
    uint64_t caller_gas_used = 0;
    int backup_status = kBftSuccess;
    do 
    {
        int balance_status = GetTempAccountBalance(
            local_tx_ptr->tx.from(),
            acc_balance_map,
            &from_balance);
        if (balance_status != kBftSuccess) {
            if (tx_info.status() != (uint32_t)balance_status) {
                return kBftLeaderInfoInvalid;
            }

            backup_status = tx_info.status();
            break;
        }

        auto account_info = block::AccountManager::Instance()->GetAcountInfo(
            local_tx_ptr->tx.from());
        if (!account_info->locked()) {
            return kBftLeaderInfoInvalid;
        }

        for (int32_t i = 0; i < local_tx_ptr->tx.storages_size(); ++i) {
            if (local_tx_ptr->tx.storages(i).key() == kContractCallerChangeAmount) {
                caller_balance_add = common::StringUtil::ToInt64(local_tx_ptr->tx.storages(i).value());
                if (local_tx_ptr->tx.status() == kBftSuccess) {
                    if (caller_balance_add < 0) {
                        if (from_balance < (uint64_t)(-caller_balance_add)) {
                            return kBftError;
                        }

                        from_balance -= (uint64_t)(-caller_balance_add);
                    } else {
                        from_balance += (uint64_t)(caller_balance_add);
                    }
                }
            }

            if (local_tx_ptr->tx.storages(i).key() == kContractCallerGasUsed) {
                caller_gas_used = common::StringUtil::ToUint64(local_tx_ptr->tx.storages(i).value());
                if (from_balance >= caller_gas_used * local_tx_ptr->tx.gas_price()) {
                    from_balance -= caller_gas_used * local_tx_ptr->tx.gas_price();
                } else {
                    assert(local_tx_ptr->tx.status() != kBftSuccess);
                    from_balance = 0;
                    if (tx_info.status() != kBftAccountBalanceError) {
                        return kBftLeaderInfoInvalid;
                    }

                    backup_status = tx_info.status();
                    break;
                }
            }
        }
    } while (0);
    
    if (from_balance != tx_info.balance()) {
        return kBftLeaderInfoInvalid;
    }

    if (caller_gas_used != tx_info.gas_used()) {
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.call_contract_step() != contract::kCallStepContractFinal) {
        return kBftLeaderInfoInvalid;
    }

    if (backup_status != (int)tx_info.status()) {
        return kBftLeaderInfoInvalid;
    }

    acc_balance_map[local_tx_ptr->tx.from()] = from_balance;
    return kBftSuccess;
}

int TxBft::BackupNormalCheck(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, bool>& locked_account_map,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    if (tx_info.gas_price() != common::GlobalInfo::Instance()->gas_price()) {
        BFT_ERROR("gas price error!");
        return kBftLeaderInfoInvalid;
    }

    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    int backup_status = kBftSuccess;
    gas_used = kTransferGas;
    if (!local_tx_ptr->tx.to_add()) {
        if (locked_account_map.find(local_tx_ptr->tx.from()) != locked_account_map.end()) {
            BFT_ERROR("contract has locked[%s]",
                common::Encode::HexEncode(local_tx_ptr->tx.from()).c_str());
            return kBftContractAddressLocked;
        }

        auto account_info = block::AccountManager::Instance()->GetAcountInfo(
            local_tx_ptr->tx.from());
        if (account_info->locked()) {
            locked_account_map[local_tx_ptr->tx.from()] = true;
            return kBftError;
        }

        do
        {
            int balance_status = GetTempAccountBalance(
                local_tx_ptr->tx.from(),
                acc_balance_map,
                &from_balance);
            if (balance_status != kBftSuccess) {
                if (tx_info.status() != (uint32_t)balance_status) {
                    BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
                        tx_info.status(), balance_status);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            for (int32_t i = 0; i < local_tx_ptr->tx.attr_size(); ++i) {
                gas_used += (local_tx_ptr->tx.attr(i).key().size() +
                    local_tx_ptr->tx.attr(i).value().size()) * kKeyValueStorageEachBytes;
            }

            if (from_balance < local_tx_ptr->tx.gas_limit() * tx_info.gas_price()) {
                if (tx_info.status() != kBftUserSetGasLimitError) {
                    BFT_ERROR("gas_limit error and status ne[%d][%d]!",
                        tx_info.status(), kBftUserSetGasLimitError);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }

            if (local_tx_ptr->tx.gas_limit() < gas_used) {
                if (tx_info.status() != kBftUserSetGasLimitError) {
                    BFT_ERROR("gas_limit error and status ne[%d][%d]!",
                        tx_info.status(), kBftUserSetGasLimitError);
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                break;
            }
        } while (0);
    } else {
        int balance_status = GetTempAccountBalance(
            local_tx_ptr->tx.to(),
            acc_balance_map,
            &to_balance);
        if (balance_status != kBftSuccess) {
            if (tx_info.status() != (uint32_t)balance_status) {
                BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
                    tx_info.status(), balance_status);
                return kBftLeaderInfoInvalid;
            }
        }
    }

    if (local_tx_ptr->tx.to_add()) {
        if (tx_info.status() == kBftSuccess) {
            if (tx_info.balance() != to_balance + local_tx_ptr->tx.amount()) {
                BFT_ERROR("balance error and status ne[%llu][%llu]!",
                    tx_info.balance(),
                    to_balance + local_tx_ptr->tx.amount());
                return kBftAccountBalanceError;
            }

            to_balance = to_balance + local_tx_ptr->tx.amount();
            acc_balance_map[local_tx_ptr->tx.to()] = to_balance;
        }

        if (tx_info.balance() != to_balance) {
            BFT_ERROR("transfer kBftAccountBalanceError invalid[%lu: %lu]!",
                tx_info.balance(), to_balance);
            return kBftLeaderInfoInvalid;
        }
    } else {
        if (tx_info.status() == kBftSuccess) {
            uint64_t real_transfer_amount = local_tx_ptr->tx.amount()+ gas_used * tx_info.gas_price();
            if (from_balance < real_transfer_amount) {
                BFT_ERROR("transfer kBftAccountBalanceError invalid!");
                return kBftLeaderInfoInvalid;
            }
            
            from_balance -= real_transfer_amount;
        } else {
            if (from_balance >= gas_used * tx_info.gas_price()) {
                if (tx_info.status() == kBftAccountBalanceError) {
                    uint64_t real_transfer_amount = local_tx_ptr->tx.amount() + gas_used * tx_info.gas_price();
                    if (from_balance >= real_transfer_amount) {
                        BFT_ERROR("transfer kBftAccountBalanceError invalid!");
                        return kBftLeaderInfoInvalid;
                    }

                    backup_status = tx_info.status();
                }

                from_balance -= gas_used * tx_info.gas_price();
            } else {
                if (backup_status == kBftSuccess && tx_info.status() != kBftAccountBalanceError) {
                    BFT_ERROR("transfer kBftAccountBalanceError invalid!");
                    return kBftLeaderInfoInvalid;
                }

                backup_status = tx_info.status();
                from_balance = 0;
            }
        }
        
        if (tx_info.balance() != from_balance) {
            BFT_ERROR("balance error and status ne[%llu][%llu]!",
                tx_info.balance(), from_balance);
            return kBftLeaderInfoInvalid;
        }
        
        if (tx_info.gas_used() != gas_used) {
            BFT_ERROR("transfer gas_used invalid!");
            return kBftLeaderInfoInvalid;
        }

        if (backup_status != (int)tx_info.status()) {
            BFT_ERROR("backup_status[%d] != tx_info.status()[%d]!", backup_status, tx_info.status());
            return kBftLeaderInfoInvalid;
        }

        acc_balance_map[local_tx_ptr->tx.from()] = from_balance;
    }
    

    push_bft_item_vec(local_tx_ptr->tx.gid());
    return kBftSuccess;
}

int TxBft::CheckBlockInfo(const protobuf::Block& block_info) {
    // check hash
    auto hash256 = GetBlockHash(block_info);
    if (hash256 != block_info.hash()) {
        BFT_ERROR("hash256 != block_info.hash() failed!");
        return kBftBlockHashError;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &pool_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        BFT_ERROR("GetBlockInfo failed!");
        return kBftBlockHashError;
    }

    if (pool_hash != block_info.prehash()) {
        res = sync::KeyValueSync::Instance()->AddSync(
                block_info.network_id(),
                block_info.prehash(),
                sync::kSyncHighest);
        if (res != sync::kSyncBlockReloaded) {
            return kBftBlockPreHashError;
        }

        res = block::AccountManager::Instance()->GetBlockInfo(
                pool_index(),
                &pool_height,
                &pool_hash,
                &tm);
        if (res != block::kBlockSuccess) {
            BFT_ERROR("GetBlockInfo failed!");
            return kBftBlockHashError;
        }

        if (pool_hash != block_info.prehash()) {
            BFT_ERROR("hash block missing pool[%d] now[%s], prev[%s]",
                    pool_index(),
                    common::Encode::HexEncode(pool_hash).c_str(),
                    common::Encode::HexEncode(block_info.prehash()).c_str());
            return kBftBlockPreHashError;
        }
    }

    if (pool_height + 1 != block_info.height()) {
        return kBftBlockHeightError;
    }
    return kBftSuccess;
}

int TxBft::CheckTxInfo(
        const protobuf::Block& block_info,
        const protobuf::TxInfo& tx_info,
        TxItemPtr* local_tx) {
    uint32_t call_contract_step = 0;
    if (tx_info.type() == common::kConsensusCallContract ||
            tx_info.type() == common::kConsensusCreateContract) {
        if (tx_info.call_contract_step() <= contract::kCallStepDefault) {
            return kBftLeaderInfoInvalid;
        }

        call_contract_step = tx_info.call_contract_step() - 1;
    }

    auto local_tx_info = DispatchPool::Instance()->GetTx(
        pool_index(),
        tx_info.to_add(),
        tx_info.type(),
        call_contract_step,
        tx_info.gid());
    *local_tx = local_tx_info;
    if (local_tx_info == nullptr) {
        BFT_ERROR("prepare [to: %d] [pool idx: %d] type: %d,"
            "call_contract_step: %d not has tx[%s]to[%s][%s]!",
            tx_info.to_add(),
            pool_index(),
            tx_info.type(),
            call_contract_step,
            common::Encode::HexEncode(tx_info.from()).c_str(),
            common::Encode::HexEncode(tx_info.to()).c_str(),
            common::Encode::HexEncode(tx_info.gid()).c_str());
        return kBftTxNotExists;
    }

    if (local_tx_info->tx.amount() != tx_info.amount()) {
        BFT_ERROR("local tx balance[%llu] not equal to leader[%llu]!",
                local_tx_info->tx.amount(), tx_info.amount());
        return kBftLeaderInfoInvalid;
    }

    if (local_tx_info->tx.from() != tx_info.from()) {
        BFT_ERROR("local tx  from not equal to leader from account![%s][%s]",
            common::Encode::HexEncode(local_tx_info->tx.from()).c_str(),
            common::Encode::HexEncode(tx_info.from()).c_str());
        return kBftLeaderInfoInvalid;
    }

    if (local_tx_info->tx.to() != tx_info.to()) {
        BFT_ERROR("local tx  to not equal to leader to account![%s][%s]",
            common::Encode::HexEncode(local_tx_info->tx.to()).c_str(),
            common::Encode::HexEncode(tx_info.to()).c_str());
        return kBftLeaderInfoInvalid;
    }

    // just from account can set attrs
    if (!tx_info.to_add()) {
        if (local_tx_info->attr_map.size() != static_cast<uint32_t>(tx_info.attr_size())) {
            BFT_ERROR("local tx attrs not equal to leader attrs[%d][%d]!",
                local_tx_info->attr_map.size(), tx_info.attr_size());
            return kBftLeaderInfoInvalid;
        }

        for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
            auto iter = local_tx_info->attr_map.find(tx_info.attr(i).key());
            if (iter == local_tx_info->attr_map.end()) {
                BFT_ERROR("local tx bft key[%s] not equal to leader key!",
                    tx_info.attr(i).key().c_str());
                return kBftLeaderInfoInvalid;
            }

            if (iter->second != tx_info.attr(i).value()) {
                BFT_ERROR("local tx bft value[%s] not equal to leader value[%s]!",
                    iter->second.c_str(), tx_info.attr(i).value().c_str());
                return kBftLeaderInfoInvalid;
            }
        }

        if (tx_info.type() == common::kConsensusCreateContract) {
            if (local_tx_info->attr_map.find(kContractBytesCode) == local_tx_info->attr_map.end()) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    BFT_ERROR("local tx bft status[%d] not equal to leader status[%d]!",
                        kBftCreateContractKeyError, tx_info.status());
                    return kBftLeaderInfoInvalid;
                }
            }

            if (security::Secp256k1::Instance()->GetContractAddress(
                    local_tx_info->tx.from(),
                    local_tx_info->tx.gid(),
                    local_tx_info->attr_map[kContractBytesCode]) != local_tx_info->tx.to()) {
                if (tx_info.status() != kBftCreateContractKeyError) {
                    BFT_ERROR("local tx bft status[%d] not equal to leader status[%d]!",
                        kBftCreateContractKeyError, tx_info.status());
                    return kBftLeaderInfoInvalid;
                }
            }
        }
    }

    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (tx_info.type() != common::kConsensusCreateAcount) {
            BFT_ERROR("local tx bft type not equal to leader tx bft type!");
            return kBftLeaderInfoInvalid;
        }
    } else {
        if (local_tx_info->tx.type() != tx_info.type()) {
            BFT_ERROR("local tx bft type not equal to leader tx bft type!");
            return kBftLeaderInfoInvalid;
        }
    }

    if (tx_info.has_to() && !tx_info.to().empty()) {

    } else {
        // check amount is 0
        // new account address
        if (common::GetPoolIndex(tx_info.from()) != pool_index()) {
            return kBftPoolIndexError;
        }

// 		if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
// 			BFT_ERROR("create account address must root conngress.not[%u]",
// 				common::GlobalInfo::Instance()->network_id());
// 			return kBftNetwokInvalid;
// 		}

//         acc_ptr = block::AccountManager::Instance()->GetAcountInfo(tx_info.from());
//         if (acc_ptr != nullptr) {
//             return kBftAccountExists;
//         }

// 		auto hash_network_id = network::GetConsensusShardNetworkId(tx_info.from());
// 		if (hash_network_id != tx_info.netwok_id()) {
// 			BFT_ERROR("backup compute network id[%u] but leader[%u]",
// 					hash_network_id, tx_info.netwok_id());
// 			return kBftNetwokInvalid;
// 		}
//         if (tx_info.amount() != 0 || tx_info.balance() != 0) {
//             return kBftAccountBalanceError;
//         }
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &pool_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        BFT_ERROR("get account block info failed!");
        return kBftBlockHeightError;
    }

    if (pool_height + 1 != block_info.height()) {
        BFT_ERROR("block height error:[now: %d][leader: %d]",
                (pool_height + 1),
                block_info.height());
        sync::KeyValueSync::Instance()->AddSync(
                block_info.network_id(),
                block_info.hash(),
                sync::kSyncHighest);
        return kBftBlockHeightError;
    }

    add_item_index_vec(local_tx_info->index);
    return kBftSuccess;
}

int TxBft::LeaderCreatePreCommit(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    bft_str = bft_msg.SerializeAsString();
    return kBftSuccess;
}

int TxBft::LeaderCreateCommit(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    bft_str = bft_msg.SerializeAsString();
    return kBftSuccess;
}

void TxBft::RootLeaderCreateAccountAddressBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    protobuf::Block& tenon_block = *(ltx_msg.mutable_block());
    auto tx_list = tenon_block.mutable_tx_list();
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx = tx_vec[i]->tx;
        tx.set_version(common::kTransactionVersion);
        tx.set_status(kBftSuccess);
        // create address must to and have transfer amount
        if (!tx.to_add() ||
                (tx.amount() <= 0 && tx.type() != common::kConsensusCreateContract)) {
            continue;
        }

        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx.to());
        if (acc_info != nullptr) {
            continue;
        }

        if (tx.type() == common::kConsensusCreateContract) {
            uint32_t network_id = 0;
            if (block::AccountManager::Instance()->GetAddressConsensusNetworkId(
                    tx.from(),
                    &network_id) != block::kBlockSuccess) {
                BFT_ERROR("get network_id error!");
                continue;
            }

            // same to from address's network id
            tx.set_network_id(network_id);
        } else {
            tx.set_network_id(NewAccountGetNetworkId(tx.to()));
        }

        auto add_tx = tx_list->Add();
        *add_tx = tx;
    }

    if (tx_list->empty()) {
        BFT_ERROR("leader has no tx to consensus.");
        return;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_idx,
        &pool_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        assert(false);
        return;
    }

    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(vss::VssManager::Instance()->EpochRandom());
    tenon_block.set_height(pool_height + 1);
    tenon_block.set_timestamp(common::TimeStampMsec());
    tenon_block.set_hash(GetBlockHash(tenon_block));
}

void TxBft::RootLeaderCreateElectConsensusShardBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    if (tx_vec.size() != 1) {
        return;
    }

    protobuf::Block& tenon_block = *(ltx_msg.mutable_block());
    protobuf::TxInfo tx = tx_vec[0]->tx;
    tx.set_version(common::kTransactionVersion);
    tx.set_amount(0);
    tx.set_gas_limit(0);
    tx.set_gas_used(0);
    tx.set_balance(0);
    tx.set_status(kBftSuccess);
    // create address must to and have transfer amount
    if (tx.type() != common::kConsensusRootElectShard) {
        return;
    }

    // (TODO): check elect is valid in the time block period,
    // one time block, one elect block
    // check after this shard statistic block coming
    auto tx_list = tenon_block.mutable_tx_list();
    auto add_tx = tx_list->Add();
    *add_tx = tx;
    if (tx_list->empty()) {
        BFT_ERROR("leader has no tx to consensus.");
        return;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_idx,
        &pool_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        assert(false);
        return;
    }

    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(vss::VssManager::Instance()->EpochRandom());
    tenon_block.set_height(pool_height + 1);
    tenon_block.set_timestamp(common::TimeStampMsec());
    tenon_block.set_hash(GetBlockHash(tenon_block));
}

void TxBft::RootLeaderCreateTxBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    if (tx_vec.size() == 1) {
        switch (tx_vec[0]->tx.type())
        {
        case common::kConsensusRootElectRoot:
            break;
        case common::kConsensusRootElectShard:
            RootLeaderCreateElectConsensusShardBlock(pool_idx, tx_vec, ltx_msg);
            break;
        case common::kConsensusRootTimeBlock:
            RootLeaderCreateTimerBlock(pool_idx, tx_vec, ltx_msg);
            break;
        case common::kConsensusRootVssBlock:
            break;
        default:
            RootLeaderCreateAccountAddressBlock(pool_idx, tx_vec, ltx_msg);
            break;
        }
    } else {
        RootLeaderCreateAccountAddressBlock(pool_idx, tx_vec, ltx_msg);
    }
}

void TxBft::RootLeaderCreateTimerBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    if (tx_vec.size() != 1) {
        return;
    }

    protobuf::Block& tenon_block = *(ltx_msg.mutable_block());
    protobuf::TxInfo tx = tx_vec[0]->tx;
    tx.set_version(common::kTransactionVersion);
    tx.set_amount(0);
    tx.set_gas_limit(0);
    tx.set_gas_used(0);
    tx.set_balance(0);
    tx.set_status(kBftSuccess);
    // create address must to and have transfer amount
    if (tx.type() != common::kConsensusRootTimeBlock) {
        return;
    }

    // (TODO): check elect is valid in the time block period,
    // one time block, one elect block
    // check after this shard statistic block coming
    auto tx_list = tenon_block.mutable_tx_list();
    auto add_tx = tx_list->Add();
    *add_tx = tx;
    if (tx_list->empty()) {
        BFT_ERROR("leader has no tx to consensus.");
        return;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_idx,
        &pool_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        assert(false);
        return;
    }

    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(vss::VssManager::Instance()->EpochRandom());
    tenon_block.set_height(pool_height + 1);
    tenon_block.set_timestamp(common::TimeStampMsec());
    tenon_block.set_hash(GetBlockHash(tenon_block));
}

int TxBft::GetTempAccountBalance(
        const std::string& id,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        uint64_t* balance) {
    auto iter = acc_balance_map.find(id);
    if (iter == acc_balance_map.end()) {
        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(id);
        if (acc_info == nullptr) {
            BFT_ERROR("account addres not exists[%s]", common::Encode::HexEncode(id).c_str());
            return kBftAccountNotExists;
        }

        uint64_t db_balance = 0;
        if (acc_info->GetBalance(&db_balance) != block::kBlockSuccess) {
            BFT_ERROR("account addres exists but balance not exists[%s]",
                common::Encode::HexEncode(id).c_str());
            return kBftAccountNotExists;
        }

        acc_balance_map[id] = db_balance;
        *balance = db_balance;
    } else {
        *balance = iter->second;
    }

    return kBftSuccess;
}

void TxBft::LeaderCreateTxBlock(
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    protobuf::Block& tenon_block = *(ltx_msg.mutable_block());
    auto tx_list = tenon_block.mutable_tx_list();
    std::unordered_map<std::string, int64_t> acc_balance_map;
    std::unordered_map<std::string, bool> locked_account_map;
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx = tx_vec[i]->tx;
        tx.set_version(common::kTransactionVersion);
        tx.set_gas_price(common::GlobalInfo::Instance()->gas_price());
        tx.set_status(kBftSuccess);
        if (tx.type() == common::kConsensusCallContract ||
                tx.type() == common::kConsensusCreateContract) {
            if (LeaderAddCallContract(
                    tx_vec[i],
                    acc_balance_map,
                    locked_account_map,
                    tx) != kBftSuccess) {
                continue;
            }
        } else {
            if (LeaderAddNormalTransaction(
                    tx_vec[i],
                    acc_balance_map,
                    locked_account_map,
                    tx) != kBftSuccess) {
                continue;
            }
        }

        auto add_tx = tx_list->Add();
        *add_tx = tx;
    }

    std::string pool_hash;
    uint64_t pool_height = 0;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &pool_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        assert(false);
        return;
    }

    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(vss::VssManager::Instance()->EpochRandom());
    tenon_block.set_height(pool_height + 1);
    tenon_block.set_timestamp(common::TimeStampMsec());
    tenon_block.set_hash(GetBlockHash(tenon_block));
}

int TxBft::LeaderAddNormalTransaction(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    if (!tx_info->tx.to_add()) {
        if (locked_account_map.find(tx.from()) != locked_account_map.end()) {
            BFT_ERROR("contract has locked[%s]", common::Encode::HexEncode(tx_info->tx.to()).c_str());
            return kBftContractAddressLocked;
        }

        auto account_info = block::AccountManager::Instance()->GetAcountInfo(tx.from());
        if (account_info->locked()) {
            locked_account_map[tx.from()] = true;
            return kBftError;
        }

        int balance_status = GetTempAccountBalance(tx.from(), acc_balance_map, &from_balance);
        if (balance_status != kBftSuccess) {
            tx.set_status(balance_status);
            // will never happen
            assert(false);
            return kBftError;
        }

        do 
        {
            gas_used = kTransferGas;
            if (!tx_info->attr_map.empty()) {
                for (auto iter = tx_info->attr_map.begin();
                    iter != tx_info->attr_map.end(); ++iter) {
                    gas_used += (iter->first.size() + iter->second.size()) *
                        kKeyValueStorageEachBytes;
                }
            }

            if (from_balance < tx_info->tx.gas_limit()  * tx.gas_price()) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }

            if (tx.gas_limit() < gas_used) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }
        } while (0);
    } else {
        int balance_status = GetTempAccountBalance(tx.to(), acc_balance_map, &to_balance);
        if (balance_status != kBftSuccess) {
            tx.set_status(balance_status);
            assert(false);
            return kBftError;
        }
    }

    if (!tx_info->tx.to_add()) {
        if (tx.status() == kBftSuccess) {
            uint64_t dec_amount = tx_info->tx.amount() + gas_used * tx.gas_price();
            if (from_balance >= gas_used * tx.gas_price()) {
                if (from_balance >= dec_amount) {
                    from_balance -= dec_amount;
                } else {
                    from_balance -= gas_used * tx.gas_price();
                    tx.set_status(kBftAccountBalanceError);
                    BFT_ERROR("leader balance error: %llu, %llu", from_balance, dec_amount);
                }
            } else {
                from_balance = 0;
                tx.set_status(kBftAccountBalanceError);
                BFT_ERROR("leader balance error: %llu, %llu", from_balance, gas_used * tx.gas_price());
            }
        } else {
            if (from_balance >= gas_used * tx.gas_price()) {
                    from_balance -= gas_used * tx.gas_price();
            } else {
                from_balance = 0;
            }
        }

        acc_balance_map[tx_info->tx.from()] = from_balance;
        tx.set_balance(from_balance);
        tx.set_gas_used(gas_used);
    } else {
        if (tx.status() == kBftSuccess) {
            to_balance += tx_info->tx.amount();
        }

        acc_balance_map[tx_info->tx.to()] = to_balance;
        tx.set_balance(to_balance);
        tx.set_gas_used(0);
    }

    return kBftSuccess;
}

int TxBft::LeaderAddCallContract(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& out_tx) {
    switch (tx_info->tx.call_contract_step()) {
    case contract::kCallStepDefault:
        return LeaderCallContractDefault(tx_info, acc_balance_map, locked_account_map, out_tx);
    case contract::kCallStepCallerInited:
        return LeaderCallContractExceute(tx_info, acc_balance_map, out_tx);
    case contract::kCallStepContractCalled:
        return LeaderCallContractCalled(tx_info, acc_balance_map, out_tx);
    default:
        break;
    }

    return kBftError;
}

int TxBft::LeaderCallContractDefault(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& tx) {
    if (locked_account_map.find(tx.from()) != locked_account_map.end()) {
        BFT_ERROR("contract has locked[%s]", common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftContractAddressLocked;
    }

    auto account_info = block::AccountManager::Instance()->GetAcountInfo(tx.from());
    if (account_info->locked()) {
        locked_account_map[tx.from()] = true;
        return kBftError;
    }

    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(tx.from(), acc_balance_map, &from_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    uint64_t gas_used = kCallContractDefaultUseGas;
    for (auto iter = tx_info->attr_map.begin();
            iter != tx_info->attr_map.end(); ++iter) {
        gas_used += (iter->first.size() + iter->second.size()) *
            kKeyValueStorageEachBytes;
    }

    // at least kCallContractDefaultUseGas + kTransferGas to call contract.
    if (from_balance < tx.gas_limit() * tx.gas_price() ||
            from_balance <= (gas_used + kTransferGas) * tx.gas_price() ||
            tx.gas_limit() < (gas_used + kTransferGas)) {
        BFT_ERROR("from balance error from_balance: %lu,"
            "tx.gas_limit() * tx.gas_price(): %lu,"
            "(gas_used + kTransferGas) * tx.gas_price(): %lu,"
            "tx.gas_limit(): %lu, (gas_used + kTransferGas): %lu",
            from_balance,
            ((gas_used + kTransferGas) * tx.gas_price()),
            ((gas_used + kTransferGas) * tx.gas_price()),
            tx.gas_limit(),
            (gas_used + kTransferGas));
        tx.set_status(kBftAccountBalanceError);
    }

    if (from_balance >= gas_used * tx.gas_price()) {
        from_balance -= gas_used * tx.gas_price();
    } else {
        from_balance = 0;
        tx.set_status(kBftAccountBalanceError);
    }
    
    acc_balance_map[tx_info->tx.from()] = from_balance;
    tx.set_balance(from_balance);
    tx.set_gas_used(gas_used);
    tx.set_call_contract_step(contract::kCallStepCallerInited);
    if (tx.status() == kBftSuccess) {
        tx.set_gas_limit(tx_info->tx.gas_limit() - gas_used);
        locked_account_map[tx.from()] = true;
    }

    return kBftSuccess;
}

int TxBft::InitTenonTvmContext(tvm::TenonHost& tenon_host) {
    uint64_t last_height = 0;
    std::string pool_hash;
    uint64_t tm = 0;
    uint32_t last_pool_index = common::kInvalidPoolIndex;
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &last_height,
        &pool_hash,
        &tm);
    if (res != block::kBlockSuccess) {
        assert(false);
        return kBftError;
    }

    tvm::Uint64ToEvmcBytes32(
        tenon_host.tx_context_.tx_gas_price,
        common::GlobalInfo::Instance()->gas_price());
    tenon_host.tx_context_.tx_origin = evmc::address{};
    tenon_host.tx_context_.block_coinbase = evmc::address{};
    tenon_host.tx_context_.block_number = last_height;
    tenon_host.tx_context_.block_timestamp = tm;
    tenon_host.tx_context_.block_gas_limit = 0;
    tenon_host.tx_context_.block_difficulty = evmc_uint256be{};
    uint64_t chanin_id = (((uint64_t)common::GlobalInfo::Instance()->network_id()) << 32 |
        (uint64_t)last_pool_index);
    tvm::Uint64ToEvmcBytes32(
        tenon_host.tx_context_.chain_id,
        chanin_id);
    return kBftSuccess;
}

int TxBft::LeaderCallContractExceute(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t caller_balance = tx_info->tx.balance();
    uint64_t contract_balance = 0;
    int balance_status = GetTempAccountBalance(
        tx_info->tx.to(),
        acc_balance_map,
        &contract_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    evmc_result evmc_res = {};
    evmc::result res{ evmc_res };
    tvm::TenonHost tenon_host;
    InitTenonTvmContext(tenon_host);
    do
    {
        if (caller_balance < tx_info->tx.gas_limit() * tx.gas_price()) {
            BFT_ERROR("caller_balance: %lu <= tx_info->tx.gas_limit() * tx.gas_price(): %lu ",
                caller_balance, tx_info->tx.gas_limit() * tx.gas_price());
            tx.set_status(kBftUserSetGasLimitError);
            break;
        }

        if (tx_info->tx.type() == common::kConsensusCallContract) {
            // will return from address's remove tenon and gas used
            tenon_host.AddTmpAccountBalance(
                tx_info->tx.from(),
                caller_balance);
            tenon_host.AddTmpAccountBalance(
                tx_info->tx.to(),
                contract_balance);
            int call_res = CallContract(tx_info, &tenon_host, &res);
            gas_used = tx_info->tx.gas_limit() - res.gas_left;
            if (call_res != kBftSuccess) {
                BFT_ERROR("call contract failed![%d]", call_res);
                tx.set_status(kBftExecuteContractFailed);
                break;
            }

            if (res.status_code != EVMC_SUCCESS) {
                BFT_ERROR("call contract failed! res.status_code[%d]", res.status_code);
                tx.set_status(kBftExecuteContractFailed);
                break;
            }
        } else {
            if (tx_info->attr_map.find(kContractBytesCode) == tx_info->attr_map.end()) {
                tx.set_status(kBftCreateContractKeyError);
                break;
            }

            if (security::Secp256k1::Instance()->GetContractAddress(
                    tx_info->tx.from(),
                    tx_info->tx.gid(),
                    tx_info->attr_map[kContractBytesCode]) != tx_info->tx.to()) {
                tx.set_status(kBftCreateContractKeyError);
                break;
            }

            tenon_host.AddTmpAccountBalance(
                tx_info->tx.from(),
                caller_balance);
            int call_res = CreateContractCallExcute(
                tx_info,
                tx.gas_limit() - gas_used,
                tx_info->attr_map[kContractBytesCode],
                &tenon_host,
                &res);
            gas_used += tx.gas_limit() - gas_used - res.gas_left;
            if (call_res != kBftSuccess) {
                tx.set_status(kBftCreateContractKeyError);
                break;
            }

            if (res.status_code != EVMC_SUCCESS) {
                tx.set_status(kBftExecuteContractFailed);
                break;
            }

            if (gas_used > tx_info->tx.gas_limit()) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }

            auto bytes_code_attr = tx.add_storages();
            bytes_code_attr->set_id(tx_info->tx.to());
            bytes_code_attr->set_key(kContractCreatedBytesCode);
            bytes_code_attr->set_value(tenon_host.create_bytes_code_);
        }
    } while (0);

    // use execute contract transfer amount to change from balance
    int64_t contract_balance_add = 0;
    int64_t caller_balance_add = 0;
    if (tx.status() == kBftSuccess) {
        for (auto account_iter = tenon_host.accounts_.begin();
                account_iter != tenon_host.accounts_.end(); ++account_iter) {
            for (auto storage_iter = account_iter->second.storage.begin();
                    storage_iter != account_iter->second.storage.end(); ++storage_iter) {
                std::string id(
                    (char*)account_iter->first.bytes,
                    sizeof(account_iter->first.bytes));
                std::string key(
                    (char*)storage_iter->first.bytes,
                    sizeof(storage_iter->first.bytes));
                std::string value(
                    (char*)storage_iter->second.value.bytes,
                    sizeof(storage_iter->second.value.bytes));
                auto attr = tx.add_storages();
                attr->set_id(id);
                attr->set_key(key);
                attr->set_value(value);
            }
        }

        for (auto transfer_iter = tenon_host.to_account_value_.begin();
                transfer_iter != tenon_host.to_account_value_.end(); ++transfer_iter) {
            // transfer from must caller or contract address, other not allowed.
            assert(transfer_iter->first == tx_info->tx.from() ||
                transfer_iter->first == tx_info->tx.to());
            for (auto to_iter = transfer_iter->second.begin();
                    to_iter != transfer_iter->second.end(); ++to_iter) {
                assert(transfer_iter->first != to_iter->first);
                if (tx_info->tx.to() == transfer_iter->first) {
                    contract_balance_add -= to_iter->second;
                }

                if (tx_info->tx.to() == to_iter->first) {
                    contract_balance_add += to_iter->second;
                }

                if (tx_info->tx.from() == transfer_iter->first) {
                    caller_balance_add -= to_iter->second;
                }

                if (tx_info->tx.from() == to_iter->first) {
                    caller_balance_add += to_iter->second;
                }

                auto trans_item = tx.add_transfers();
                trans_item->set_from(transfer_iter->first);
                trans_item->set_to(to_iter->first);
                trans_item->set_amount(to_iter->second);
            }
        }

        if ((int64_t)caller_balance + caller_balance_add - tx_info->tx.amount() >= gas_used * tx.gas_price()) {
        } else {
            if (tx.status() == kBftSuccess) {
                tx.set_status(kBftAccountBalanceError);
            }
        }

        if (tx.status() == kBftSuccess) {
            if (caller_balance_add < 0) {
                if (caller_balance < (uint64_t)(-caller_balance_add) + tx_info->tx.amount()) {
                    if (tx.status() == kBftSuccess) {
                        tx.set_status(kBftAccountBalanceError);
                    }
                }
            }
        }

        if (tx.status() == kBftSuccess) {
            if (tx_info->tx.amount() > 0) {
                if (caller_balance < tx_info->tx.amount()) {
                    if (tx.status() == kBftSuccess) {
                        tx.set_status(kBftAccountBalanceError);
                    }
                }
            }
        }

        if (tx.status() == kBftSuccess) {
            if (contract_balance_add < 0) {
                if (contract_balance < (uint64_t)(-contract_balance_add)) {
                    if (tx.status() == kBftSuccess) {
                        tx.set_status(kBftAccountBalanceError);
                    }
                } else {
                    contract_balance -= (uint64_t)(-contract_balance_add);
                }
            } else {
                contract_balance += contract_balance_add;
            }
        }
    } else {
        if (caller_balance >= gas_used * tx.gas_price()) {
        } else {
            if (tx.status() == kBftSuccess) {
                tx.set_status(kBftAccountBalanceError);
            }
        }
    }

    contract_balance += tx_info->tx.amount();
    auto caller_balance_attr = tx.add_storages();
    caller_balance_attr->set_key(kContractCallerChangeAmount);
    caller_balance_attr->set_value(std::to_string(caller_balance_add - (int64_t)tx_info->tx.amount()));
    auto gas_limit_attr = tx.add_storages();
    gas_limit_attr->set_key(kContractCallerGasUsed);
    gas_limit_attr->set_value(std::to_string(gas_used));
    acc_balance_map[tx_info->tx.to()] = contract_balance;
    tx.set_balance(contract_balance);
    tx.set_gas_used(0);
    tx.set_call_contract_step(contract::kCallStepContractCalled);
    return kBftSuccess;
}

int TxBft::CreateContractCallExcute(
        const TxItemPtr& tx_info,
        uint64_t gas_limit,
        const std::string& bytes_code,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res) {
    std::string input;
    uint32_t call_mode = tvm::kJustCreate;
    auto iter = tx_info->attr_map.find(kContractInputCode);
    if (iter != tx_info->attr_map.end()) {
        input = iter->second;
        call_mode = tvm::kCreateAndCall;
    }
    tvm::Execution exec;
    int exec_res = exec.execute(
        bytes_code,
        input,
        tx_info->tx.from(),
        tx_info->tx.to(),
        tx_info->tx.from(),
        tx_info->tx.amount(),
        gas_limit,
        0,
        call_mode,
        *tenon_host,
        out_res);
    if (exec_res != tvm::kTvmSuccess) {
        return kBftError;
    }

    return kBftSuccess;
}

int TxBft::CallContract(
        const TxItemPtr& tx_info,
        tvm::TenonHost* tenon_host,
        evmc::result* out_res) {
    std::string input;
    auto iter = tx_info->attr_map.find(kContractInputCode);
    if (iter != tx_info->attr_map.end()) {
        input = iter->second;
    }

    auto contract_info = block::AccountManager::Instance()->GetAcountInfo(tx_info->tx.to());
    if (contract_info == nullptr) {
        BFT_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

    uint32_t address_type = block::kNormalAddress;
    if (contract_info->GetAddressType(&address_type) != block::kBlockSuccess) {
        BFT_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

    std::string bytes_code;
    if (contract_info->GetBytesCode(&bytes_code) != block::kBlockSuccess) {
        BFT_ERROR("contract address not exists[%s]",
            common::Encode::HexEncode(tx_info->tx.to()).c_str());
        return kBftError;
    }

    tvm::Execution exec;
    int exec_res = exec.execute(
        bytes_code,
        input,
        tx_info->tx.from(),
        tx_info->tx.to(),
        tx_info->tx.from(),
        tx_info->tx.amount(),
        tx_info->tx.gas_limit(),
        0,
        tvm::kJustCall,
        *tenon_host,
        out_res);
    if (exec_res != tvm::kTvmSuccess) {
        return kBftError;
    }

    return kBftSuccess;
}

int TxBft::LeaderCallContractCalled(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    // gas just consume by from
    uint64_t from_balance = 0;
    int balance_status = GetTempAccountBalance(tx_info->tx.from(), acc_balance_map, &from_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    auto account_info = block::AccountManager::Instance()->GetAcountInfo(tx_info->tx.from());
    if (!account_info->locked()) {
        return kBftError;
    }

    int64_t caller_balance_add = 0;
    uint64_t caller_gas_used = 0;
    for (int32_t i = 0; i < tx_info->tx.storages_size(); ++i) {
        if (tx_info->tx.storages(i).key() == kContractCallerChangeAmount) {
            caller_balance_add = common::StringUtil::ToInt64(tx_info->tx.storages(i).value());
            if (tx_info->tx.status() == kBftSuccess) {
                if (caller_balance_add < 0) {
                    if (from_balance < (uint64_t)(-caller_balance_add)) {
                        return kBftError;
                    }

                    from_balance -= (uint64_t)(-caller_balance_add);
                } else {
                    from_balance += (uint64_t)(caller_balance_add);
                }
            }
        }

        if (tx_info->tx.storages(i).key() == kContractCallerGasUsed) {
            caller_gas_used = common::StringUtil::ToUint64(tx_info->tx.storages(i).value());
            if (from_balance >= caller_gas_used * tx_info->tx.gas_price()) {
                from_balance -= caller_gas_used * tx_info->tx.gas_price();
            } else {
                assert(tx_info->tx.status() != kBftSuccess);
                from_balance = 0;
                if (tx.status() == kBftSuccess) {
                    tx.set_status(kBftAccountBalanceError);
                }
            }
        }
    }

    acc_balance_map[tx_info->tx.from()] = from_balance;
    tx.set_balance(from_balance);
    tx.set_gas_used(caller_gas_used);
    tx.set_call_contract_step(contract::kCallStepContractFinal);
    return kBftSuccess;
}

}  // namespace bft

}  //namespace tenon
