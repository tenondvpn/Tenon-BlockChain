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
    all_msg += tx_info.gid() + std::to_string(tx_info.status()) + tx_info.from() +
        std::to_string(tx_info.balance()) + std::to_string(tx_info.gas_limit()) +
        std::to_string(tx_info.gas_price()) + tx_info.to() +
        std::to_string(tx_info.amount()) + std::to_string(tx_info.type());
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

    BLS_DEBUG("TTTT GetPrepareTxsHash gid: %s, type: %d, status: %d, from: %s, balance: %lu, gas limit: %lu, gas price: %lu, to: %s, amount: %lu, attr size: %d",
        common::Encode::HexEncode(tx_info.gid()).c_str(), tx_info.type(),
        tx_info.status(), common::Encode::HexEncode(tx_info.from()).c_str(),
        tx_info.balance(), tx_info.gas_limit(), tx_info.gas_price(),
        common::Encode::HexEncode(tx_info.to()).c_str(),
        tx_info.amount(), tx_info.attr_size());
    return common::Hash::keccak256(all_msg);
}

std::string GetBlockHash(const protobuf::Block& block) {
    std::string tbft_prepare_txs_str_for_hash;
    for (int32_t i = 0; i < block.tx_list_size(); ++i) {
        auto tx_hash = GetPrepareTxsHash(block.tx_list(i));
        if (tx_hash.empty()) {
            continue;
        }

        tbft_prepare_txs_str_for_hash += tx_hash;
        std::string text_addr;
        if (block.tx_list(i).to_add()) {
            tbft_prepare_txs_str_for_hash += block.tx_list(i).to();
            text_addr = block.tx_list(i).to();
        } else {
            tbft_prepare_txs_str_for_hash += block.tx_list(i).from();
            text_addr = block.tx_list(i).from();
        }

        BLS_DEBUG("TTTT tx hash: %s, addr: %s, balance: %lu",
            common::Encode::HexEncode(tx_hash).c_str(),
            common::Encode::HexEncode(text_addr).c_str(),
            block.tx_list(i).balance());
    }

    if (tbft_prepare_txs_str_for_hash.empty()) {
        return "";
    }

    std::string block_info = block.prehash() +
        std::to_string(block.timeblock_height()) +
        std::to_string(block.electblock_height()) +
        std::to_string(block.network_id()) +
        std::to_string(block.pool_index()) +
        std::to_string(block.height());
    tbft_prepare_txs_str_for_hash += block_info;
    BFT_DEBUG("TTTT block_info: %s, prehash: %s, timeblock_height: %lu, electblock_height: %lu, network_id: %d, pool_index: %d, height: %lu, get block hash: %s",
        common::Encode::HexEncode(block_info).c_str(),
        common::Encode::HexEncode(block.prehash()).c_str(),
        block.timeblock_height(),
        block.electblock_height(),
        block.network_id(),
        block.pool_index(),
        block.height(),
        common::Encode::HexEncode(common::Hash::keccak256(tbft_prepare_txs_str_for_hash)).c_str());
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
