#pragma once

#include <map>
#include <memory>

#include "evmc/evmc.h"

#include "bft/tx_bft.h"
#include "db/db.h"
#include "big_num/bignum_utils.h"
#include "contract/contract_utils.h"
#include "contract/call_parameters.h"

namespace tenon {

namespace contract {

class ContractInterface {
public:
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info,
            db::DbWriteBach& db_batch) = 0;
    virtual int GetAttrWithKey(const std::string& key, std::string& value) = 0;
    // attr map can change, and save to block chain
    virtual int Execute(bft::TxItemPtr& tx_item) = 0;
    virtual int call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) = 0;

protected:
    ContractInterface(const std::string& create_address) : create_address_(create_address) {}
    virtual ~ContractInterface() {}

    uint64_t ComputeGasUsed(uint32_t base, uint32_t word, uint32_t data_size) {
        return static_cast<uint64_t>(base + (data_size + 31) / 32 * word);
    }

    bigint ParseBigEndianRightPadded(
            const std::string& in,
            const bigint& begin,
            const bigint& count) {
        if (begin > in.size()) {
            return 0;
        }

        assert(count <= std::numeric_limits<size_t>::max() / 8);
        std::string cropped = in.substr(begin, (std::min)(count, in.size() - begin));
        bigint ret = bignum::FromBigEndian<bigint>(cropped);
        assert(count - cropped.size() <= std::numeric_limits<size_t>::max() / 8);
        ret <<= 8 * (count - cropped.size());
        return ret;
    }

    bigint ExpLengthAdjust(
            const bigint& exp_offset,
            const bigint& exp_length,
            const std::string& in) {
        if (exp_length <= 32) {
            bigint const exp(ParseBigEndianRightPadded(in, exp_offset, exp_length));
            return exp ? boost::multiprecision::msb(exp) : 0;
        } else {
            bigint const expFirstWord(ParseBigEndianRightPadded(in, exp_offset, 32));
            size_t const highestBit(expFirstWord ? boost::multiprecision::msb(expFirstWord) : 0);
            return 8 * (exp_length - 32) + highestBit;
        }
    }

    bigint MultComplexity(const bigint& x) {
        if (x <= 64) {
            return x * x;
        }

        if (x <= 1024) {
            return (x * x) / 4 + 96 * x - 3072;
        } else {
            return (x * x) / 16 + 480 * x - 199680;
        }
    }

    std::string create_address_;

    DISALLOW_COPY_AND_ASSIGN(ContractInterface);
};

typedef std::shared_ptr<ContractInterface> ContractInterfacePtr;

}  // namespace contract

}  // namespace tenon
