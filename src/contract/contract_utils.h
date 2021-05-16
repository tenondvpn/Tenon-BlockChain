#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/encode.h"

#define CONTRACT_DEBUG(fmt, ...) TENON_DEBUG("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_INFO(fmt, ...) TENON_INFO("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_WARN(fmt, ...) TENON_WARN("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_ERROR(fmt, ...) TENON_ERROR("[CONRTACT]" fmt, ## __VA_ARGS__)

namespace lego {

namespace contract {

enum ContractErrorCode {
    kContractSuccess = 0,
    kContractError = 1,
    kContractNotExists = 2,
};

enum CallContractStep {
    kCallStepDefault = 0,
    kCallStepCallerInited = 1,
    kCallStepContractCalled = 2,
};

static const std::string kContractVpnBandwidthProveAddr = "contract_vpn_bandwith_prove";
static const std::string kContractVpnPayfor = "contract_vpn_payfor";
static const std::string kToUseBandwidthOneDay = "to_use_bw_one_day";
static const std::string kVpnClientLoginManager = "kVpnClientLoginManager";
static const std::string kVpnMining = "kVpnMining";
static const std::string kContractEcrecover = common::Encode::HexDecode("0000000000000000000000000000000000000001");

}  // namespace contact

}  // namespace lego
