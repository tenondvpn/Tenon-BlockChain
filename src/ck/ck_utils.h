#pragma once

#include <clickhouse/client.h>

#include "common/utils.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace ck {

static const std::string kClickhouseTableName = "tenon_ck_block_table";

};  // namespace ck

};  // namespace tenon
