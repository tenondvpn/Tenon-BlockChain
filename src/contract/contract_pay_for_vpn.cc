#include "stdafx.h"
#include "contract/contract_pay_for_vpn.h"

#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/user_property_key_define.h"
#include "db/db_utils.h"
#include "contract/contract_utils.h"

namespace tenon {

namespace contract {

int PayforVpn::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    if (tx_info.type() != common::kConsensusPayForCommonVpn) {
        return kContractSuccess;
    }

    if (tx_info.to_add()) {
        return kContractSuccess;
    }

    uint64_t day_msec = 24llu * 3600llu * 1000llu;
    uint64_t pay_day_timestamp = block_item.timestamp() / day_msec;
    std::string key = db::kGlobalContractForPayforVpn + "_" + tx_info.from();
    PayInfo pay_info;
    pay_info.day_timestamp = pay_day_timestamp;
    pay_info.amount = tx_info.amount();
    pay_info.height = block_item.height();
    uint64_t use_day = tx_info.amount() / common::kVpnVipMinPayfor;
    pay_info.end_day_timestamp = pay_day_timestamp + use_day;
    std::string val((char*)&pay_info, sizeof(pay_info));
    db_batch.Put(key, val);
    return kContractSuccess;
}

int PayforVpn::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int PayforVpn::Execute(bft::TxItemPtr tx_item) {
    if (tx_item->tx.type() != common::kConsensusPayForCommonVpn) {
        return kContractError;
    }

    if (tx_item->tx.to_add()) {
        return kContractSuccess;
    }

    std::string key = db::kGlobalContractForPayforVpn + "_" + tx_item->tx.from();
    std::string val;
    auto st = db::Db::Instance()->Get(key, &val);
    if (!st.ok() || val.size() != sizeof(PayInfo)) {
        return kContractSuccess;
    }

    PayInfo* pay_info = (PayInfo*)val.c_str();
    auto now_day_timestamp = common::TimeUtils::TimestampDays() + 1;
    if (pay_info->end_day_timestamp > now_day_timestamp) {
        CONTRACT_ERROR("user[%s] vpn pay for[%s] prev paied not end.[%u] now[%u]",
                common::Encode::HexEncode(tx_item->tx.from()).c_str(),
                common::Encode::HexEncode(tx_item->tx.to()).c_str(),
                pay_info->end_day_timestamp,
                now_day_timestamp);
        return kContractError;
    }

    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
