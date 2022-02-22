#include "bft/bft_utils.h"

#include "block/account_manager.h"
#include "election/elect_manager.h"
#include "network/network_utils.h"
#include "vss/vss_manager.h"

namespace tenon {

namespace bft {

std::string StatusToString(uint32_t status) {
    switch (status) {
    case kBftInit:
        return "bft_init";
    case kBftPrepare:
        return "bft_prepare";
    case kBftPreCommit:
        return "bft_precommit";
    case kBftCommit:
        return "bft_commit";
    case kBftCommited:
        return "bft_success";
    default:
        return "unknown";
    }
}

// hash128(gid + from + to + amount + type + attrs(k:v))
std::string GetTxMessageHash(const protobuf::TxInfo& tx_info) {
    std::string message = common::Encode::HexEncode(tx_info.gid()) + "-" +
        common::Encode::HexEncode(tx_info.from()) + "-" +
        common::Encode::HexEncode(tx_info.to()) + "-" +
        std::to_string(tx_info.amount()) + "-" +
        std::to_string(tx_info.gas_limit()) + "-" +
        std::to_string(tx_info.gas_price()) + "-" +
        std::to_string(tx_info.type()) + "-";
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        message += common::Encode::HexEncode(tx_info.attr(i).key()) +
            common::Encode::HexEncode(tx_info.attr(i).value());
    }

    for (int32_t i = 0; i < tx_info.transfers_size(); ++i) {
        message += common::Encode::HexEncode(tx_info.transfers(i).from()) +
            common::Encode::HexEncode(tx_info.transfers(i).to()) +
            std::to_string(tx_info.transfers(i).amount());
    }

    for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
        message += common::Encode::HexEncode(tx_info.storages(i).key()) +
            common::Encode::HexEncode(tx_info.storages(i).value());
    }

    return common::Hash::keccak256(message);
}

std::string GetPrepareTxsHash(const protobuf::TxInfo& tx_info) {
    std::string all_msg;
    block::DbAccountInfoPtr account_info = nullptr;
    if (tx_info.to_add()) {
        account_info = block::AccountManager::Instance()->GetAcountInfo(tx_info.from());
    } else {
        account_info = block::AccountManager::Instance()->GetAcountInfo(tx_info.to());
    }

    uint64_t balance = 0;
    if (account_info != nullptr) {
        if (!account_info->GetBalance(&balance) != block::kBlockSuccess) {
            return "";
        }
    }

    // just use before tx balance
    all_msg += tx_info.gid() + std::to_string(tx_info.status()) + tx_info.from() +
        std::to_string(balance) + std::to_string(tx_info.gas_limit()) +
        std::to_string(tx_info.gas_price()) + tx_info.to() +
        std::to_string(tx_info.amount());
    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        all_msg += tx_info.attr(i).key() + tx_info.attr(i).value();
    }

    for (int32_t i = 0; i < tx_info.storages_size(); ++i) {
        all_msg += tx_info.storages(i).key() + tx_info.storages(i).value();
    }

    for (int32_t i = 0; i < tx_info.transfers_size(); ++i) {
        all_msg += tx_info.transfers(i).from() + tx_info.transfers(i).to() +
            std::to_string(tx_info.transfers(i).amount());
    }

    return common::Hash::keccak256(all_msg);
}

// prehash + network_id + height + random + elect version + txes's hash
std::string GetBlockHash(const protobuf::Block& block) {
    std::string tbft_prepare_txs_str_for_hash;
    for (int32_t i = 0; i < block.tx_list_size(); ++i) {
        auto tx_hash = GetPrepareTxsHash(block.tx_list(i));
        if (tx_hash.empty()) {
            continue;
        }

        tbft_prepare_txs_str_for_hash += block.tx_list(i).gid() + tx_hash +
            std::to_string(block.tx_list(i).balance());
        if (block.tx_list(i).to_add()) {
            tbft_prepare_txs_str_for_hash += block.tx_list(i).to();
        } else {
            tbft_prepare_txs_str_for_hash += block.tx_list(i).from();
        }
    }

    if (tbft_prepare_txs_str_for_hash.empty()) {
        return nullptr;
    }

    std::string block_info = block.prehash() +
        std::to_string(block.timeblock_height()) +
        std::to_string(block.electblock_height()) +
        std::to_string(block.network_id()) +
        std::to_string(block.pool_index()) +
        std::to_string(block.height());
    tbft_prepare_txs_str_for_hash += block_info;
    return common::Hash::keccak256(tbft_prepare_txs_str_for_hash);
}

uint32_t NewAccountGetNetworkId(const std::string& addr) {
    return static_cast<uint32_t>((common::Hash::Hash64(addr) *
        vss::VssManager::Instance()->EpochRandom()) %
        common::GlobalInfo::Instance()->consensus_shard_count()) +
        network::kConsensusShardBeginNetworkId;
}

bool IsRootSingleBlockTx(uint32_t tx_type) {
    if (tx_type == common::kConsensusRootElectShard ||
            tx_type == common::kConsensusRootTimeBlock) {
        return true;
    }

    return false;
}

bool IsShardSingleBlockTx(uint32_t tx_type) {
    return IsRootSingleBlockTx(tx_type);
}

}  // namespace bft

}  //namespace tenon
