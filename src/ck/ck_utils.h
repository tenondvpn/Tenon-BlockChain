#pragma once

#include <clickhouse/client.h>

#include "common/utils.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace ck {

static const std::string kClickhouseTransTableName = "tenon_ck_transaction_table";
static const std::string kClickhouseBlockTableName = "tenon_ck_block_table";
static const std::string kClickhouseAccountTableName = "tenon_ck_account_table";
static const std::string kClickhouseAccountKvTableName = "tenon_ck_account_key_value_table";
static const std::string kClickhouseStatisticTableName = "tenon_ck_statistic_table";
static const std::string kClickhouseShardStatisticTableName = "tenon_ck_shard_statistic_table";
static const std::string kClickhousePoolStatisticTableName = "tenon_ck_pool_statistic_table";

};  // namespace ck

};  // namespace tenon
