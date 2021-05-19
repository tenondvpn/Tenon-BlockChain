#pragma once
#include "common/utils.h"
#include "common/log.h"

#define DB_DEBUG(fmt, ...) TENON_DEBUG("[db]" fmt, ## __VA_ARGS__)
#define DB_INFO(fmt, ...) TENON_INFO("[db]" fmt, ## __VA_ARGS__)
#define DB_WARN(fmt, ...) TENON_WARN("[db]" fmt, ## __VA_ARGS__)
#define DB_ERROR(fmt, ...) TENON_ERROR("[db]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace db {

static const char kDbFieldLinkLetter = '\x01';
static const std::string kGlobalDbKeyVersion("V3");
// for global level db dict key
static const std::string kGlobalDickKeyAccountInfo = kGlobalDbKeyVersion + "_kAI";
static const std::string kGlobalDickKeyAccountIdExists = kGlobalDbKeyVersion + "_kAE";
static const std::string kGlobalDickKeyPoolInfo = kGlobalDbKeyVersion + "_kPI";
static const std::string kGlobalDbQueueKeyPrefix = kGlobalDbKeyVersion + "_kQP";
static const std::string kGlobalDbSaveVpnNodesKey = kGlobalDbKeyVersion + "_kSVNK";
// for global queue name
static const std::string kGlobalDbQueueStatistics(kGlobalDbQueueKeyPrefix + kGlobalDbKeyVersion + "_kST1");
static const std::string kGlobalDbPriQueuePrefix = kGlobalDbKeyVersion + "_kPQ";
static const std::string kGlobalDbAcountHeightPriQueue = kGlobalDbKeyVersion + "_kAHPQ";
static const std::string kGlobalDbElectBlock = kGlobalDbKeyVersion + "_kElectBlock";
static const std::string kGlobalDbAccountInitBlocks = kGlobalDbKeyVersion + "_kAccInitBlocks";

// for contract
static const std::string kGlobalContractForPayforVpn = kGlobalDbKeyVersion + "_kCtrPayVpn";
static const std::string kGlobalContractForVpnMining = kGlobalDbKeyVersion + "_kVpnMining";

}

}
