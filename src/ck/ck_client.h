#pragma once

#include <clickhouse/client.h>

#include "common/utils.h"
#include "ck/ck_utils.h"
#include "block/proto/block.pb.h"

namespace tenon {

namespace ck {

class ClickHouseClient {
public:
    ClickHouseClient(const std::string& host, const std::string& user, const std::string& passwd);
    ~ClickHouseClient();
    bool CreateTable();
    bool AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_item);

private:
    void CheckBlockFinished();
    bool CreateTransactionTable();
    bool CreateBlockTable();

    clickhouse::Client client_;

    DISALLOW_COPY_AND_ASSIGN(ClickHouseClient);
};

};  // namespace ck

};  // namespace tenon
