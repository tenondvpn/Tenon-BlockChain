#include "stdafx.h"
#include "bft/tx_bft.h"

#include "common/global_info.h"
#include "common/random.h"
#include "contract/contract_manager.h"
#include "contract/contract_utils.h"
#include "block/account_manager.h"
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

namespace lego {

namespace bft {

TxBft::TxBft() {}

TxBft::~TxBft() {}

int TxBft::Init(bool leader) {
    std::vector<TxItemPtr> tx_vec;
    uint32_t pool_index = 0;
    DispatchPool::Instance()->GetTx(pool_index, tx_vec);
    if (tx_vec.empty()) {
        return kBftNoNewTxs;
    }
    return kBftSuccess;
}

int TxBft::Prepare(bool leader, std::string& prepare) {
    if (leader) {
        return LeaderCreatePrepare(prepare);
    }

    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        if (RootBackupCheckPrepare(prepare) != kBftSuccess) {
            return kBftError;
        }
    } else {
        if (BackupCheckPrepare(prepare) != kBftSuccess) {
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

int TxBft::LeaderCreatePrepare(std::string& bft_str) {
    uint32_t pool_index = 0;
    std::vector<TxItemPtr> tx_vec;
    DispatchPool::Instance()->GetTx(pool_index, tx_vec);
    if (tx_vec.empty()) {
        return kBftNoNewTxs;
    }

    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        add_item_index_vec(tx_vec[i]->index);
        push_bft_item_vec(tx_vec[i]->tx.gid());
    }

    set_pool_index(pool_index);
    bft::protobuf::TxBft tx_bft;
    auto& ltx_prepare = *(tx_bft.mutable_ltx_prepare());
    if (common::GlobalInfo::Instance()->network_id() == network::kRootCongressNetworkId) {
        RootLeaderCreateNewAccountTxBlock(pool_index, tx_vec, ltx_prepare);
    } else {
        LeaderCreateTxBlock(pool_index, tx_vec, ltx_prepare);
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(ltx_prepare.block());
    SetBlock(block_ptr);
    bft_str = tx_bft.SerializeAsString();
    set_prepare_hash(ltx_prepare.block().hash());
    return kBftSuccess;
}

int TxBft::RootBackupCheckPrepare(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    if (!bft_msg.ParseFromString(bft_str)) {
        BFT_ERROR("bft::protobuf::BftMessage ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!bft_msg.has_data()) {
        BFT_ERROR("bft::protobuf::BftMessage has no data!");
        return kBftInvalidPackage;
    }

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

        if (local_tx_info->tx.to() != tx_info.to()) {
            BFT_ERROR("local to is not equal leader to.");
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

int TxBft::BackupCheckPrepare(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    if (!bft_msg.ParseFromString(bft_str)) {
        BFT_ERROR("bft::protobuf::BftMessage ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!bft_msg.has_data()) {
        BFT_ERROR("bft::protobuf::BftMessage has no data!");
        return kBftInvalidPackage;
    }

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

        if (local_tx_info->tx.type() != common::kConsensusCallContract) {
            int check_res = BackupNormalCheck(local_tx_info, tx_info, acc_balance_map);
            if (check_res != kBftSuccess) {
                return check_res;
            }
        } else {
            switch (local_tx_info->tx.call_contract_step()) {
            case contract::kCallStepDefault: {
                int check_res = BackupCheckContractDefault(local_tx_info, tx_info, acc_balance_map);
                if (check_res != kBftSuccess) {
                    BFT_ERROR("BackupCheckContractDefault transaction failed![%d]", tmp_res);
                    return check_res;
                }
                break;
            }
            case contract::kCallStepCallerInited: {
                int check_res = BackupCheckContractInited(
                    local_tx_info,
                    tx_info,
                    acc_balance_map,
                    locked_account_map);
                if (check_res != kBftSuccess) {
                    BFT_ERROR("BackupCheckContractInited transaction failed![%d]", tmp_res);
                    return check_res;
                }
                break;
            }
            case contract::kCallStepContractLocked: {
                int check_res = BackupCheckContractLocked(local_tx_info, tx_info, acc_balance_map);
                if (check_res != kBftSuccess) {
                    BFT_ERROR("BackupCheckContractLocked transaction failed![%d]", tmp_res);
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
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    int check_res = BackupNormalCheck(local_tx_ptr, tx_info, acc_balance_map);
    if (check_res != kBftSuccess) {
        return check_res;
    }
    
    if (tx_info.call_contract_step() != contract::kCallStepCallerInited) {
        return kBftLeaderInfoInvalid;
    }

    return kBftSuccess;
}

int TxBft::BackupCheckContractInited(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map) {
    // lock contract and 
    if (locked_account_map.find(local_tx_ptr->tx.to()) != locked_account_map.end()) {
        if (tx_info.status() != kBftContractAddressLocked) {
            BFT_ERROR("backup account locked error.");
            return kBftLeaderInfoInvalid;
        }
    }

    auto contract_acc = block::AccountManager::Instance()->GetContractInfoByAddress(
        local_tx_ptr->tx.to());
    if (contract_acc == nullptr) {
        BFT_ERROR("backup get contract address error.");
        return kBftLeaderInfoInvalid;
    }

    if (contract_acc->locked()) {
        if (tx_info.status() != kBftContractAddressLocked) {
            BFT_ERROR("backup account locked by block commit error.");
            return kBftLeaderInfoInvalid;
        }
    }

    std::string bytes_code;
    if (contract_acc->GetBytesCode(&bytes_code) != block::kBlockSuccess) {
        if (tx_info.status() != kBftContractBytesCodeError) {
            BFT_ERROR("backup get bytescode error.");
            return kBftLeaderInfoInvalid;
        }
    }

    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(
        local_tx_ptr->tx.to(),
        acc_balance_map,
        &to_balance);
    if (balance_status != kBftSuccess && tx_info.status() != (uint32_t)balance_status) {
        BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
            tx_info.status(), balance_status);
        return kBftLeaderInfoInvalid;
    }

    bool bytes_code_ok = false;
    bool balance_ok = false;
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        if (tx_info.attr(i).key() == kContractBytesCode) {
            if (tx_info.attr(i).value() == bytes_code) {
                bytes_code_ok = true;
            }
        }

        if (tx_info.attr(i).key() == kContractBalance) {
            if (tx_info.attr(i).value() == std::to_string(to_balance)) {
                balance_ok = true;
            }
        }
    }

    if (!bytes_code_ok || !balance_ok) {
        BFT_ERROR("backup get bytes_code_ok error or balance_ok error[%d][%d].",
            bytes_code_ok, balance_ok);
        return kBftLeaderInfoInvalid;
    }

    locked_account_map[local_tx_ptr->tx.to()] = true;
    // account lock must new block coming
    return kBftSuccess;
}

int TxBft::BackupCheckContractLocked(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(
        local_tx_ptr->tx.from(),
        acc_balance_map,
        &from_balance);
    if (balance_status != kBftSuccess && tx_info.status() != (uint32_t)balance_status) {
        BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
            tx_info.status(), balance_status);
        return kBftLeaderInfoInvalid;
    }

    auto local_tx_info = DispatchPool::Instance()->GetTx(
        pool_index(),
        local_tx_ptr->tx.to_add(),
        local_tx_ptr->tx.type(),
        local_tx_ptr->tx.call_contract_step(),
        local_tx_ptr->tx.gid());
    evmc_result evmc_res = {};
    evmc::result res{ evmc_res };
    tvm::TenonHost tenon_host;
    do
    {
        if (from_balance <= local_tx_ptr->tx.gas_limit()) {
            if (tx_info.status() != kBftUserSetGasLimitError) {
                return kBftLeaderInfoInvalid;
            }

            break;
        }

        if (local_tx_info->attr_map.find(kContractBytesCode) == local_tx_info->attr_map.end()) {
            if (tx_info.status() != kBftExecuteContractFailed) {
                return kBftLeaderInfoInvalid;
            }

            break;
        }

        // will return from address's remove tenon and gas used
        tenon_host.AddTmpAccountBalance(
            local_tx_info->tx.from(),
            from_balance);
        tenon_host.AddTmpAccountBalance(
            local_tx_info->tx.to(),
            common::StringUtil::ToUint64(local_tx_info->attr_map[kContractBalance]));
        int call_res = CallContract(local_tx_info, &tenon_host, &res);
        gas_used = local_tx_info->tx.gas_limit() - res.gas_left;
        if (call_res != kBftSuccess) {
            if (tx_info.status() != kBftExecuteContractFailed) {
                return kBftLeaderInfoInvalid;
            }

            break;
        }

        if (res.status_code != EVMC_SUCCESS) {
            if (tx_info.status() != kBftExecuteContractFailed) {
                return kBftLeaderInfoInvalid;
            }

            break;
        }
    } while (0);

    // use execute contract transfer amount to change from balance
    if (tx_info.status() == kBftSuccess) {
        evmc_address sender;
        memcpy(sender.bytes, local_tx_ptr->tx.from().c_str(), sizeof(sender.bytes));
        auto account_iter = tenon_host.accounts_.find(sender);
        if (account_iter == tenon_host.accounts_.end()) {
            if (tx_info.storages_size() != 0) {
                return kBftLeaderInfoInvalid;
            }
        }

        if (account_iter->second.storage.size() != (uint32_t)tx_info.storages_size()) {
            return kBftLeaderInfoInvalid;
        }

        // storage just caller can add
        for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
            evmc::bytes32 key;
            memcpy(key.bytes, tx_info.storages(i).key().c_str(), sizeof(key.bytes));
            auto iter = account_iter->second.storage.find(key);
            if (iter == account_iter->second.storage.end()) {
                return kBftLeaderInfoInvalid;
            }

            std::string value((char*)iter->second.value.bytes, sizeof(iter->second.value.bytes));
            if (value != tx_info.storages(i).value()) {
                return kBftLeaderInfoInvalid;
            }
        }

        int64_t caller_balance_add = 0;
        auto& transfers = tenon_host.to_account_value_;
        if ((uint32_t)tx_info.transfers_size() != transfers.size()) {
            return kBftLeaderInfoInvalid;
        }

        for (int32_t i = 0; i < tx_info.transfers_size(); ++i) {
            auto iter = transfers.find(tx_info.transfers(i).from());
            if (iter == transfers.end()) {
                return kBftLeaderInfoInvalid;
            }

            auto to_iter = iter->second.find(tx_info.transfers(i).to());
            if (to_iter == iter->second.end()) {
                return kBftLeaderInfoInvalid;
            }

            if (to_iter->second != to_iter->second) {
                return kBftLeaderInfoInvalid;
            }

            if (tx_info.from() == iter->first) {
                caller_balance_add -= to_iter->second;
            }

            if (tx_info.from() == to_iter->first) {
                caller_balance_add += to_iter->second;
            }
        }

        uint64_t dec_amount = tx_info.amount() + gas_used;
        if (caller_balance_add < 0) {
            dec_amount += caller_balance_add;
        } else {
            from_balance += caller_balance_add;
        }

        if (from_balance >= gas_used) {
            if (from_balance >= dec_amount) {
                from_balance -= dec_amount;
            } else {
                from_balance -= gas_used;
                if (tx_info.status() != kBftAccountBalanceError) {
                    return kBftLeaderInfoInvalid;
                }
            }
        } else {
            gas_used = from_balance;
            from_balance = 0;
            if (tx_info.status() != kBftAccountBalanceError) {
                return kBftLeaderInfoInvalid;
            }
        }
    } else {
        if (from_balance >= gas_used) {
            from_balance -= gas_used;
        } else {
            gas_used = from_balance;
            from_balance = 0;
            if (tx_info.status() != kBftAccountBalanceError) {
                return kBftLeaderInfoInvalid;
            }
        }
    }

    if (from_balance != tx_info.balance()) {
        return kBftLeaderInfoInvalid;
    }

    if (tx_info.gas_used() != gas_used) {
        return kBftLeaderInfoInvalid;
    }

    acc_balance_map[local_tx_ptr->tx.from()] = from_balance;
    return kBftSuccess;
}

int TxBft::BackupCheckContractCalled(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    // gas just consume by from
    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(
        local_tx_ptr->tx.to(),
        acc_balance_map,
        &to_balance);
    if (balance_status != kBftSuccess) {
        if (tx_info.status() != (uint32_t)balance_status) {
            return kBftLeaderInfoInvalid;
        }
    }

    if (tx_info.status() != kBftSuccess) {
        return kBftSuccess;
    }

    int64_t contract_balance_add = 0;
    for (int32_t i = 0; i < tx_info.transfers_size(); ++i) {
        if (local_tx_ptr->tx.to() == tx_info.transfers(i).from()) {
            contract_balance_add -= tx_info.transfers(i).amount();
        }

        if (local_tx_ptr->tx.to() == tx_info.transfers(i).to()) {
            contract_balance_add += tx_info.transfers(i).amount();
        }
    }

    if (contract_balance_add < 0) {
        assert(to_balance > (uint64_t)abs(contract_balance_add));
    }

    to_balance += contract_balance_add;
    if (tx_info.balance() != to_balance) {
        return kBftLeaderInfoInvalid;
    }

    acc_balance_map[tx_info.to()] = to_balance;
    if (tx_info.gas_used() != 0) {
        return kBftLeaderInfoInvalid;
    }

    return kBftSuccess; 
}

int TxBft::BackupNormalCheck(
        const TxItemPtr& local_tx_ptr,
        const protobuf::TxInfo& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    if (!local_tx_ptr->tx.to_add()) {
        int balance_status = GetTempAccountBalance(
            local_tx_ptr->tx.from(),
            acc_balance_map,
            &from_balance);
        if (balance_status != kBftSuccess && tx_info.status() != (uint32_t)balance_status) {
            BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
                tx_info.status(), balance_status);
            return kBftLeaderInfoInvalid;
        }

        gas_used = kTransferGas;
        for (int32_t i = 0; i < local_tx_ptr->tx.attr_size(); ++i) {
            gas_used += (local_tx_ptr->tx.attr(i).key().size() +
                local_tx_ptr->tx.attr(i).value().size()) * kKeyValueStorageEachBytes;
        }

        if (local_tx_ptr->tx.gas_limit() < gas_used) {
            if (tx_info.status() != kBftUserSetGasLimitError) {
                BFT_ERROR("gas_limit error and status ne[%d][%d]!",
                    tx_info.status(), kBftUserSetGasLimitError);
                return kBftLeaderInfoInvalid;
            }
        }
    } else {
        int balance_status = GetTempAccountBalance(
            local_tx_ptr->tx.to(),
            acc_balance_map,
            &to_balance);
        if (balance_status != kBftSuccess && tx_info.status() != (uint32_t)balance_status) {
            BFT_ERROR("GetTempAccountBalance error and status ne[%d][%d]!",
                tx_info.status(), balance_status);
            return kBftLeaderInfoInvalid;
        }
    }

    if (local_tx_ptr->tx.to_add()) {
        if (tx_info.balance() != to_balance + local_tx_ptr->tx.amount()) {
            BFT_ERROR("balance error and status ne[%llu][%llu]!",
                tx_info.balance(), to_balance + local_tx_ptr->tx.amount());
            return kBftAccountBalanceError;
        }

        to_balance = to_balance + local_tx_ptr->tx.amount();
    } else {
        uint64_t real_transfer_amount = local_tx_ptr->tx.amount();
        if (local_tx_ptr->tx.gas_limit() < gas_used) {
            real_transfer_amount = 0;
        }

        if (from_balance <= gas_used) {
            if (tx_info.status() != kBftAccountBalanceError) {
                BFT_ERROR("balance error and status ne[%llu][%llu]!",
                    from_balance, gas_used);
                return kBftLeaderInfoInvalid;
            }

            from_balance = 0;
        } else {
            if (from_balance < (real_transfer_amount + gas_used)) {
                if (tx_info.status() != kBftAccountBalanceError) {
                    BFT_ERROR("balance error and status ne[%llu][%llu] status[%d][%d]!",
                        from_balance, real_transfer_amount + gas_used,
                        tx_info.status(), kBftAccountBalanceError);
                    return kBftLeaderInfoInvalid;
                }

                from_balance -= gas_used;
            } else {
                from_balance -= (real_transfer_amount + gas_used);
            }
        }

        if (tx_info.balance() != from_balance) {
            BFT_ERROR("balance error and status ne[%llu][%llu]!",
                tx_info.balance(), from_balance);
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
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_index(),
        &pool_height,
        &pool_hash);
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
                &pool_hash);
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
    if (tx_info.type() == common::kConsensusCallContract) {
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
            tx_info.call_contract_step(),
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
    int res = block::AccountManager::Instance()->GetBlockInfo(
            pool_index(),
            &pool_height,
            &pool_hash);
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

void TxBft::RootLeaderCreateNewAccountTxBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    protobuf::Block& tenon_block = *(ltx_msg.mutable_block());
    auto tx_list = tenon_block.mutable_tx_list();
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx = tx_vec[i]->tx;
        tx.set_version(common::kTransactionVersion);
        tx.set_gas_price(0);
        tx.set_gas_used(0);
        tx.set_status(kBftSuccess);
        // create address must to and have transfer amount
        if (!tx.to_add() || (tx.amount() <= 0 && tx.type() != common::kConsensusCreateContract)) {
            continue;
        }

        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx.to());
        if (acc_info != nullptr) {
            continue;
        }

        tx.set_balance(0);  // just to network add balance by transfer tenon
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
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_idx,
        &pool_height,
        &pool_hash);
    if (res != block::kBlockSuccess) {
        assert(false);
        return;
    }

    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(crand::ConsistencyRandom::Instance()->Random());
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
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& ltx_msg) {
    protobuf::Block& tenon_block = *(ltx_msg.mutable_block());
    auto tx_list = tenon_block.mutable_tx_list();
    std::unordered_map<std::string, int64_t> acc_balance_map;
    std::unordered_map<std::string, bool> locked_account_map;
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx = tx_vec[i]->tx;
        tx.set_version(common::kTransactionVersion);
        tx.set_gas_price(0);
        tx.set_status(kBftSuccess);
        std::cout << "LeaderCreateTxBlock called, type: " << tx.type()
            << ", call contract step: " << tx.call_contract_step() << std::endl;
        if (tx.type() != common::kConsensusCallContract) {
            if (LeaderAddNormalTransaction(tx_vec[i], acc_balance_map, tx) != kBftSuccess) {
                continue;
            }
        } else {
            if (LeaderAddCallContract(
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
    int res = block::AccountManager::Instance()->GetBlockInfo(
        pool_idx,
        &pool_height,
        &pool_hash);
    if (res != block::kBlockSuccess) {
        assert(false);
        return;
    }

    tenon_block.set_prehash(pool_hash);
    tenon_block.set_version(common::kTransactionVersion);
    tenon_block.set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
    tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
    tenon_block.set_consistency_random(crand::ConsistencyRandom::Instance()->Random());
    tenon_block.set_height(pool_height + 1);
    tenon_block.set_timestamp(common::TimeStampMsec());
    tenon_block.set_hash(GetBlockHash(tenon_block));
}

int TxBft::LeaderAddNormalTransaction(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    if (!tx.to_add()) {
        int balance_status = GetTempAccountBalance(tx.from(), acc_balance_map, &from_balance);
        if (balance_status != kBftSuccess) {
            tx.set_status(balance_status);
            assert(false);
            return kBftError;
        }

        do 
        {
            gas_used = kTransferGas;
            if (from_balance <= tx_info->tx.gas_limit()) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }

            if (!tx_info->attr_map.empty()) {
                for (auto iter = tx_info->attr_map.begin();
                        iter != tx_info->attr_map.end(); ++iter) {
                    gas_used += (iter->first.size() + iter->second.size()) *
                        kKeyValueStorageEachBytes;
                }
            }

            if (tx.gas_limit() < gas_used) {
                tx.set_status(kBftUserSetGasLimitError);
                break;
            }

            if (tx.type() == common::kConsensusCreateContract) {
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

    if (tx.status() == kBftSuccess) {
        if (tx_info->tx.to_add()) {
            to_balance = to_balance + tx_info->tx.amount();
        } else {
            uint64_t dec_amount = tx_info->tx.amount() + gas_used;
            if (from_balance >= gas_used) {
                if (from_balance >= dec_amount) {
                    from_balance -= dec_amount;
                } else {
                    from_balance -= gas_used;
                    tx.set_status(kBftAccountBalanceError);
                }
            } else {
                gas_used = from_balance;
                from_balance = 0;
                tx.set_status(kBftAccountBalanceError);
            }
        }
    } else {
        if (from_balance >= gas_used) {
            from_balance -= gas_used;
        } else {
            gas_used = from_balance;
            from_balance = 0;
            tx.set_status(kBftAccountBalanceError);
        }
    }

    if (tx_info->tx.to_add() && tx.status() == kBftAccountNotExists) {
        // waiting root network create account address and assignment network id
        return kBftError;
    }

    if (tx_info->tx.to_add()) {
        acc_balance_map[tx_info->tx.to()] = to_balance;
        tx.set_balance(to_balance);
    } else {
        acc_balance_map[tx_info->tx.from()] = from_balance;
        tx.set_balance(from_balance);
    }

    tx.set_call_contract_step(contract::kCallStepCallerInited);
    tx.set_gas_used(gas_used);
    return kBftSuccess;
}

int TxBft::LeaderCheckCallContract(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    uint64_t gas_used = 0;
    // gas just consume by from
    uint64_t from_balance = 0;
    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(tx_info->tx.from(), acc_balance_map, &from_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    evmc_result evmc_res = {};
    evmc::result res{ evmc_res };
    tvm::TenonHost tenon_host;
    do
    {
        if (from_balance <= tx_info->tx.gas_limit()) {
            tx.set_status(kBftUserSetGasLimitError);
            break;
        }

        if (tx_info->attr_map.find(kContractBytesCode) == tx_info->attr_map.end()) {
            tx.set_status(kBftExecuteContractFailed);
            break;
        }

        // will return from address's remove tenon and gas used
        tenon_host.AddTmpAccountBalance(
            tx_info->tx.from(),
            from_balance);
        tenon_host.AddTmpAccountBalance(
            tx_info->tx.to(),
            common::StringUtil::ToUint64(tx_info->attr_map[kContractBalance]));
        int call_res = CallContract(tx_info, &tenon_host, &res);
        gas_used = tx_info->tx.gas_limit() - res.gas_left;
        if (call_res != kBftSuccess) {
            tx.set_status(kBftExecuteContractFailed);
            break;
        }

        if (res.status_code != EVMC_SUCCESS) {
            tx.set_status(kBftExecuteContractFailed);
            break;
        }
    } while (0);

    // use execute contract transfer amount to change from balance
    if (tx.status() == kBftSuccess) {
        evmc_address sender;
        memcpy(sender.bytes, tx_info->tx.from().c_str(), sizeof(sender.bytes));
        auto account_iter = tenon_host.accounts_.find(sender);
        // storage just caller can add
        if (account_iter != tenon_host.accounts_.end()) {
            for (auto storage_iter = account_iter->second.storage.begin();
                    storage_iter != account_iter->second.storage.end(); ++storage_iter) {
                std::string key(
                    (char*)storage_iter->first.bytes,
                    sizeof(storage_iter->first.bytes));
                std::string value(
                    (char*)storage_iter->second.value.bytes,
                    sizeof(storage_iter->second.value.bytes));
                auto attr = tx.add_storages();
                attr->set_key(key);
                attr->set_value(value);
            }
        }

        int64_t caller_balance_add = 0;
        for (auto transfer_iter = tenon_host.to_account_value_.begin();
                transfer_iter != tenon_host.to_account_value_.end(); ++transfer_iter) {
            // transfer from must caller or contract address, other not allowed.
            assert(transfer_iter->first == tx_info->tx.from() ||
                transfer_iter->first == tx_info->tx.to());
            for (auto to_iter = transfer_iter->second.begin();
                    to_iter != transfer_iter->second.end(); ++to_iter) {
                assert(transfer_iter->first != to_iter->first);
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

        uint64_t dec_amount = tx_info->tx.amount() + gas_used;
        if (caller_balance_add < 0) {
            dec_amount += caller_balance_add;
        } else {
            from_balance += caller_balance_add;
        }

        if (from_balance >= gas_used) {
            if (from_balance >= dec_amount) {
                from_balance -= dec_amount;
            } else {
                from_balance -= gas_used;
                tx.set_status(kBftAccountBalanceError);
            }
        } else {
            gas_used = from_balance;
            from_balance = 0;
            tx.set_status(kBftAccountBalanceError);
        }
    } else {
        if (from_balance >= gas_used) {
            from_balance -= gas_used;
        } else {
            gas_used = from_balance;
            from_balance = 0;
            tx.set_status(kBftAccountBalanceError);
        }
    }

    acc_balance_map[tx_info->tx.from()] = from_balance;
    tx.set_balance(from_balance);
    tx.set_gas_used(gas_used);
    return kBftSuccess;
}

int TxBft::LeaderAddCallContract(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        std::unordered_map<std::string, bool>& locked_account_map,
        protobuf::TxInfo& out_tx) {
    if (tx_info->tx.call_contract_step() == contract::kCallStepDefault) {
        return LeaderAddNormalTransaction(tx_info, acc_balance_map, out_tx);
    }

    if (tx_info->tx.call_contract_step() == contract::kCallStepCallerInited) {
        // lock contract and 
        if (locked_account_map.find(tx_info->tx.to()) != locked_account_map.end()) {
            BFT_ERROR("contract has locked[%s]", common::Encode::HexEncode(tx_info->tx.to()).c_str());
            return kBftContractAddressLocked;
        }

        auto contract_acc = block::AccountManager::Instance()->GetContractInfoByAddress(tx_info->tx.to());
        assert(contract_acc != nullptr);
        if (contract_acc->locked()) {
            BFT_ERROR("contract has locked[%s]", common::Encode::HexEncode(tx_info->tx.to()).c_str());
            return kBftContractAddressLocked;
        }

        std::string bytes_code;
        if (contract_acc->GetBytesCode(&bytes_code) != block::kBlockSuccess) {
            return kBftContractBytesCodeError;
        }

        uint64_t balance = 0;
        if (contract_acc->GetBalance(&balance) != block::kBlockSuccess) {
            return kBftAccountBalanceError;
        }

        auto bytes_code_attr = out_tx.add_attr();
        bytes_code_attr->set_key(kContractBytesCode);
        bytes_code_attr->set_value(bytes_code);
        auto balace_attr = out_tx.add_attr();
        balace_attr->set_key(kContractBalance);
        balace_attr->set_value(std::to_string(balance));
        locked_account_map[tx_info->tx.to()] = true;
        // account lock must new block coming
        return kBftSuccess;
    }

    if (tx_info->tx.call_contract_step() == contract::kCallStepContractLocked) {
        // now caller call contract
        return LeaderCheckCallContract(tx_info, acc_balance_map, out_tx);
    }

    if (tx_info->tx.call_contract_step() == contract::kCallStepContractCalled) {
        // contract unlock it
        return LeaderAddContractCalled(tx_info, acc_balance_map, out_tx);
    }

    return kBftError;
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

    tvm::Execution exec;
    int exec_res = exec.execute(
        tx_info->tx.to(),
        input,
        tx_info->tx.from(),
        tx_info->tx.to(),
        tx_info->tx.from(),
        tx_info->tx.amount(),
        tx_info->tx.gas_limit(),
        0,
        false,
        *tenon_host,
        out_res);
    if (exec_res != tvm::kTvmSuccess) {
        return kBftError;
    }

    return kBftSuccess;
}

int TxBft::LeaderAddContractCalled(
        TxItemPtr& tx_info,
        std::unordered_map<std::string, int64_t>& acc_balance_map,
        protobuf::TxInfo& tx) {
    // gas just consume by from
    uint64_t to_balance = 0;
    int balance_status = GetTempAccountBalance(tx_info->tx.to(), acc_balance_map, &to_balance);
    if (balance_status != kBftSuccess) {
        tx.set_status(balance_status);
        assert(false);
        return kBftError;
    }

    if (tx_info->tx.status() != kBftSuccess) {
        return kBftSuccess;
    }

    int64_t contract_balance_add = 0;
    for (int32_t i = 0; i < tx_info->tx.transfers_size(); ++i) {
        if (tx_info->tx.to() == tx_info->tx.transfers(i).from()) {
            contract_balance_add -= tx_info->tx.transfers(i).amount();
        }

        if (tx_info->tx.to() == tx_info->tx.transfers(i).to()) {
            contract_balance_add += tx_info->tx.transfers(i).amount();
        }
    }

    if (contract_balance_add < 0) {
        assert(to_balance > (uint64_t)abs(contract_balance_add));
    }

    to_balance += contract_balance_add;
    acc_balance_map[tx_info->tx.to()] = to_balance;
    tx.set_balance(to_balance);
    tx.set_gas_used(0);
    return kBftSuccess;
}

}  // namespace bft

}  //namespace lego
