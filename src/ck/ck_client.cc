#include "ck/ck_client.h"

#include "common/encode.h"

namespace tenon {

namespace ck {

ClickHouseClient::ClickHouseClient(
    const std::string& host,
    const std::string& user,
    const std::string& passwd)
//     : client_(clickhouse::ClientOptions().SetHost(host).SetUser("default").SetPassword("default123")) {}
    : client_(clickhouse::ClientOptions().SetHost(host)) {}

ClickHouseClient::~ClickHouseClient() {}

bool ClickHouseClient::AddNewBlock(const std::shared_ptr<bft::protobuf::Block>& block_item) try {
    std::string cmd;
    const auto& tx_list = block_item->tx_list();
    clickhouse::Block trans;
    clickhouse::Block blocks;
    clickhouse::Block accounts;
    clickhouse::Block account_attrs;
    auto shard_id = std::make_shared<clickhouse::ColumnUInt32>();
    auto pool_index = std::make_shared<clickhouse::ColumnUInt32>();
    auto height = std::make_shared<clickhouse::ColumnUInt64>();
    auto prehash = std::make_shared<clickhouse::ColumnString>();
    auto hash = std::make_shared<clickhouse::ColumnString>();
    auto version = std::make_shared<clickhouse::ColumnUInt32>();
    auto vss = std::make_shared<clickhouse::ColumnUInt64>();
    auto elect_height = std::make_shared<clickhouse::ColumnUInt64>();
    auto bitmap = std::make_shared<clickhouse::ColumnString>();
    auto timestamp = std::make_shared<clickhouse::ColumnUInt64>();
    auto timeblock_height = std::make_shared<clickhouse::ColumnUInt64>();
    auto bls_agg_sign_x = std::make_shared<clickhouse::ColumnString>();
    auto bls_agg_sign_y = std::make_shared<clickhouse::ColumnString>();
    auto commit_bitmap = std::make_shared<clickhouse::ColumnString>();
    auto gid = std::make_shared<clickhouse::ColumnString>();
    auto from = std::make_shared<clickhouse::ColumnString>();
    auto from_pubkey = std::make_shared<clickhouse::ColumnString>();
    auto from_sign = std::make_shared<clickhouse::ColumnString>();
    auto to = std::make_shared<clickhouse::ColumnString>();
    auto amount = std::make_shared<clickhouse::ColumnUInt64>();
    auto gas_limit = std::make_shared<clickhouse::ColumnUInt64>();
    auto gas_used = std::make_shared<clickhouse::ColumnUInt64>();
    auto gas_price = std::make_shared<clickhouse::ColumnUInt64>();
    auto balance = std::make_shared<clickhouse::ColumnUInt64>();
    auto to_add = std::make_shared<clickhouse::ColumnUInt32>();
    auto type = std::make_shared<clickhouse::ColumnUInt32>();
    auto attrs = std::make_shared<clickhouse::ColumnString>();
    auto status = std::make_shared<clickhouse::ColumnUInt32>();
    auto tx_hash = std::make_shared<clickhouse::ColumnString>();
    auto call_contract_step = std::make_shared<clickhouse::ColumnUInt32>();
    auto storages = std::make_shared<clickhouse::ColumnString>();
    auto transfers = std::make_shared<clickhouse::ColumnString>();
    auto date = std::make_shared<clickhouse::ColumnUInt32>();

    auto block_shard_id = std::make_shared<clickhouse::ColumnUInt32>();
    auto block_pool_index = std::make_shared<clickhouse::ColumnUInt32>();
    auto block_height = std::make_shared<clickhouse::ColumnUInt64>();
    auto block_prehash = std::make_shared<clickhouse::ColumnString>();
    auto block_hash = std::make_shared<clickhouse::ColumnString>();
    auto block_version = std::make_shared<clickhouse::ColumnUInt32>();
    auto block_vss = std::make_shared<clickhouse::ColumnUInt64>();
    auto block_elect_height = std::make_shared<clickhouse::ColumnUInt64>();
    auto block_bitmap = std::make_shared<clickhouse::ColumnString>();
    auto block_timestamp = std::make_shared<clickhouse::ColumnUInt64>();
    auto block_timeblock_height = std::make_shared<clickhouse::ColumnUInt64>();
    auto block_bls_agg_sign_x = std::make_shared<clickhouse::ColumnString>();
    auto block_bls_agg_sign_y = std::make_shared<clickhouse::ColumnString>();
    auto block_commit_bitmap = std::make_shared<clickhouse::ColumnString>();
    auto block_tx_size = std::make_shared<clickhouse::ColumnUInt32>();
    auto block_date = std::make_shared<clickhouse::ColumnUInt32>();

    auto acc_account = std::make_shared<clickhouse::ColumnString>();
    auto acc_shard_id = std::make_shared<clickhouse::ColumnUInt32>();
    auto acc_pool_index = std::make_shared<clickhouse::ColumnUInt32>();
    auto acc_balance = std::make_shared<clickhouse::ColumnUInt64>();

    auto attr_account = std::make_shared<clickhouse::ColumnString>();
    auto attr_shard_id = std::make_shared<clickhouse::ColumnUInt32>();
    auto attr_key = std::make_shared<clickhouse::ColumnString>();
    auto attr_value = std::make_shared<clickhouse::ColumnString>();

    std::string bitmap_str;
    for (int32_t i = 0; i < block_item->bitmap_size(); ++i) {
        bitmap_str += std::to_string(block_item->bitmap(i)) + ",";
    }

    std::string commit_bitmap_str;
    for (int32_t i = 0; i < block_item->commit_bitmap_size(); ++i) {
        commit_bitmap_str += std::to_string(block_item->commit_bitmap(i)) + ",";
    }

    block_shard_id->Append(block_item->network_id());
    block_pool_index->Append(block_item->pool_index());
    block_height->Append(block_item->height());
    block_prehash->Append(common::Encode::HexEncode(block_item->prehash()));
    block_hash->Append(common::Encode::HexEncode(block_item->hash()));
    block_version->Append(block_item->version());
    block_vss->Append(block_item->consistency_random());
    block_elect_height->Append(block_item->electblock_height());
    block_bitmap->Append(common::Encode::HexEncode(bitmap_str));
    block_commit_bitmap->Append(common::Encode::HexEncode(commit_bitmap_str));
    block_timestamp->Append(block_item->timestamp());
    block_timeblock_height->Append(block_item->timeblock_height());
    block_bls_agg_sign_x->Append(common::Encode::HexEncode(block_item->bls_agg_sign_x()));
    block_bls_agg_sign_y->Append(common::Encode::HexEncode(block_item->bls_agg_sign_y()));
    block_date->Append(common::MicTimestampToDate(block_item->timestamp()));
    block_tx_size->Append(tx_list.size());

    for (int32_t i = 0; i < tx_list.size(); ++i) {
        shard_id->Append(block_item->network_id());
        pool_index->Append(block_item->pool_index());
        height->Append(block_item->height());
        prehash->Append(common::Encode::HexEncode(block_item->prehash()));
        hash->Append(common::Encode::HexEncode(block_item->hash()));
        version->Append(block_item->version());
        vss->Append(block_item->consistency_random());
        elect_height->Append(block_item->electblock_height());
        bitmap->Append(common::Encode::HexEncode(bitmap_str));
        commit_bitmap->Append(common::Encode::HexEncode(commit_bitmap_str));
        timestamp->Append(block_item->timestamp());
        timeblock_height->Append(block_item->timeblock_height());
        bls_agg_sign_x->Append(common::Encode::HexEncode(block_item->bls_agg_sign_x()));
        bls_agg_sign_y->Append(common::Encode::HexEncode(block_item->bls_agg_sign_y()));
        date->Append(common::MicTimestampToDate(block_item->timestamp()));
        gid->Append(common::Encode::HexEncode(tx_list[i].gid()));
        from->Append(common::Encode::HexEncode(tx_list[i].from()));
        from_pubkey->Append(common::Encode::HexEncode(tx_list[i].from_pubkey()));
        from_sign->Append(common::Encode::HexEncode(tx_list[i].from_sign()));
        to->Append(common::Encode::HexEncode(tx_list[i].to()));
        amount->Append(tx_list[i].amount());
        gas_limit->Append(tx_list[i].gas_limit());
        gas_used->Append(tx_list[i].gas_used());
        gas_price->Append(tx_list[i].gas_price());
        balance->Append(tx_list[i].balance());
        to_add->Append(tx_list[i].to_add());
        type->Append(tx_list[i].type());
        attrs->Append("");
        status->Append(tx_list[i].status());
        tx_hash->Append(common::Encode::HexEncode(tx_list[i].tx_hash()));
        call_contract_step->Append(tx_list[i].call_contract_step());
        storages->Append("");
        transfers->Append("");

        if (tx_list[i].to_add()) {
            acc_account->Append(common::Encode::HexEncode(tx_list[i].to()));
            acc_shard_id->Append(block_item->network_id());
            acc_pool_index->Append(block_item->pool_index());
            acc_balance->Append(tx_list[i].balance());
        } else {
            acc_account->Append(common::Encode::HexEncode(tx_list[i].from()));
            acc_shard_id->Append(block_item->network_id());
            acc_pool_index->Append(block_item->pool_index());
            acc_balance->Append(tx_list[i].balance());

            for (int32_t i = 0; i < tx_list[i].attr_size(); ++i) {
                attr_account->Append(common::Encode::HexEncode(tx_list[i].from()));
                attr_shard_id->Append(block_item->network_id());
                attr_key->Append(tx_list[i].attr(i).key());
                attr_value->Append(tx_list[i].attr(i).value());
            }

            for (int32_t i = 0; i < tx_list[i].storages_size(); ++i) {
                attr_account->Append(common::Encode::HexEncode(tx_list[i].from()));
                attr_shard_id->Append(block_item->network_id());
                attr_key->Append(tx_list[i].storages(i).key());
                attr_value->Append(tx_list[i].storages(i).value());
            }
        }
    }

    blocks.AppendColumn("shard_id", block_shard_id);
    blocks.AppendColumn("pool_index", block_pool_index);
    blocks.AppendColumn("height", block_height);
    blocks.AppendColumn("prehash", block_prehash);
    blocks.AppendColumn("hash", block_hash);
    blocks.AppendColumn("version", block_version);
    blocks.AppendColumn("vss", block_vss);
    blocks.AppendColumn("elect_height", block_elect_height);
    blocks.AppendColumn("bitmap", block_bitmap);
    blocks.AppendColumn("timestamp", block_timestamp);
    blocks.AppendColumn("timeblock_height", block_timeblock_height);
    blocks.AppendColumn("bls_agg_sign_x", block_bls_agg_sign_x);
    blocks.AppendColumn("bls_agg_sign_y", block_bls_agg_sign_y);
    blocks.AppendColumn("commit_bitmap", block_commit_bitmap);
    blocks.AppendColumn("date", block_date);
    blocks.AppendColumn("tx_size", block_tx_size);

    trans.AppendColumn("shard_id", shard_id);
    trans.AppendColumn("pool_index", pool_index);
    trans.AppendColumn("height", height);
    trans.AppendColumn("prehash", prehash);
    trans.AppendColumn("hash", hash);
    trans.AppendColumn("version", version);
    trans.AppendColumn("vss", vss);
    trans.AppendColumn("elect_height", elect_height);
    trans.AppendColumn("bitmap", bitmap);
    trans.AppendColumn("timestamp", timestamp);
    trans.AppendColumn("timeblock_height", timeblock_height);
    trans.AppendColumn("bls_agg_sign_x", bls_agg_sign_x);
    trans.AppendColumn("bls_agg_sign_y", bls_agg_sign_y);
    trans.AppendColumn("commit_bitmap", commit_bitmap);
    trans.AppendColumn("gid", gid);
    trans.AppendColumn("from", from);
    trans.AppendColumn("from_pubkey", from_pubkey);
    trans.AppendColumn("from_sign", from_sign);
    trans.AppendColumn("to", to);
    trans.AppendColumn("amount", amount);
    trans.AppendColumn("gas_limit", gas_limit);
    trans.AppendColumn("gas_used", gas_used);
    trans.AppendColumn("gas_price", gas_price);
    trans.AppendColumn("balance", balance);
    trans.AppendColumn("to_add", to_add);
    trans.AppendColumn("type", type);
    trans.AppendColumn("attrs", attrs);
    trans.AppendColumn("status", status);
    trans.AppendColumn("tx_hash", tx_hash);
    trans.AppendColumn("call_contract_step", call_contract_step);
    trans.AppendColumn("storages", storages);
    trans.AppendColumn("transfers", transfers);
    trans.AppendColumn("date", date);

    accounts.AppendColumn("id", acc_account);
    accounts.AppendColumn("shard_id", acc_shard_id);
    accounts.AppendColumn("pool_index", acc_pool_index);
    accounts.AppendColumn("balance", acc_balance);

    account_attrs.AppendColumn("id", attr_account);
    account_attrs.AppendColumn("shard_id", attr_shard_id);
    account_attrs.AppendColumn("key", attr_key);
    account_attrs.AppendColumn("value", attr_value);

    client_.Insert(kClickhouseTransTableName, trans);
    client_.Insert(kClickhouseBlockTableName, blocks);
    client_.Insert(kClickhouseAccountTableName, accounts);
    client_.Insert(kClickhouseAccountKvTableName, account_attrs);
    return true;
} catch (std::exception& e) {
    TENON_ERROR("add new block failed[%s]", e.what());
    return false;
}

bool ClickHouseClient::CreateTransactionTable() {
    std::string create_cmd = std::string("CREATE TABLE if not exists ") + kClickhouseTransTableName + " ( "
        "`shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4), "
        "`pool_index` UInt32 COMMENT 'pool_index' CODEC(T64, LZ4), "
        "`height` UInt64 COMMENT 'height' CODEC(T64, LZ4), "
        "`prehash` String COMMENT 'prehash' CODEC(LZ4), "
        "`hash` String COMMENT 'hash' CODEC(LZ4), "
        "`version` UInt32 COMMENT 'version' CODEC(LZ4), "
        "`vss` UInt64 COMMENT 'vss' CODEC(T64, LZ4), "
        "`elect_height` UInt64 COMMENT 'elect_height' CODEC(T64, LZ4), "
        "`bitmap` String COMMENT 'success consensers' CODEC(LZ4), "
        "`timestamp` UInt64 COMMENT 'timestamp' CODEC(T64, LZ4), "
        "`timeblock_height` UInt64 COMMENT 'timeblock_height' CODEC(T64, LZ4), "
        "`bls_agg_sign_x` String COMMENT 'bls_agg_sign_x' CODEC(LZ4), "
        "`bls_agg_sign_y` String COMMENT 'bls_agg_sign_y' CODEC(LZ4), "
        "`commit_bitmap` String COMMENT 'commit_bitmap' CODEC(LZ4), "
        "`gid` String COMMENT 'gid' CODEC(LZ4), "
        "`from` String COMMENT 'from' CODEC(LZ4), "
        "`from_pubkey` String COMMENT 'from_pubkey' CODEC(LZ4), "
        "`from_sign` String COMMENT 'from_sign' CODEC(LZ4), "
        "`to` String COMMENT 'to' CODEC(LZ4), "
        "`amount` UInt64 COMMENT 'amount' CODEC(T64, LZ4), "
        "`gas_limit` UInt64 COMMENT 'gas_limit' CODEC(T64, LZ4), "
        "`gas_used` UInt64 COMMENT 'gas_used' CODEC(T64, LZ4), "
        "`gas_price` UInt64 COMMENT 'gas_price' CODEC(T64, LZ4), "
        "`balance` UInt64 COMMENT 'balance' CODEC(T64, LZ4), "
        "`to_add` UInt32 COMMENT 'to_add' CODEC(T64, LZ4), "
        "`type` UInt32 COMMENT 'type' CODEC(T64, LZ4), "
        "`attrs` String COMMENT 'attrs' CODEC(LZ4), "
        "`status` UInt32 COMMENT 'status' CODEC(T64, LZ4), "
        "`tx_hash` String COMMENT 'tx_hash' CODEC(LZ4), "
        "`call_contract_step` UInt32 COMMENT 'call_contract_step' CODEC(T64, LZ4), "
        "`storages` String COMMENT 'storages' CODEC(LZ4), "
        "`transfers` String COMMENT 'transfers' CODEC(LZ4), "
        "`date` UInt32 COMMENT 'date' CODEC(T64, LZ4) "
        ") "
        "ENGINE = ReplacingMergeTree "
        "PARTITION BY(shard_id, date) "
        "ORDER BY(pool_index,height,type,from,to) "
        "SETTINGS index_granularity = 8192;";
    client_.Execute(create_cmd);
    return true;
}

bool ClickHouseClient::CreateBlockTable() {
    std::string create_cmd = std::string("CREATE TABLE if not exists ") + kClickhouseBlockTableName + " ( "
        "`shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4), "
        "`pool_index` UInt32 COMMENT 'pool_index' CODEC(T64, LZ4), "
        "`height` UInt64 COMMENT 'height' CODEC(T64, LZ4), "
        "`prehash` String COMMENT 'prehash' CODEC(LZ4), "
        "`hash` String COMMENT 'hash' CODEC(LZ4), "
        "`version` UInt32 COMMENT 'version' CODEC(LZ4), "
        "`vss` UInt64 COMMENT 'vss' CODEC(T64, LZ4), "
        "`elect_height` UInt64 COMMENT 'elect_height' CODEC(T64, LZ4), "
        "`bitmap` String COMMENT 'success consensers' CODEC(LZ4), "
        "`timestamp` UInt64 COMMENT 'timestamp' CODEC(T64, LZ4), "
        "`timeblock_height` UInt64 COMMENT 'timeblock_height' CODEC(T64, LZ4), "
        "`bls_agg_sign_x` String COMMENT 'bls_agg_sign_x' CODEC(LZ4), "
        "`bls_agg_sign_y` String COMMENT 'bls_agg_sign_y' CODEC(LZ4), "
        "`commit_bitmap` String COMMENT 'commit_bitmap' CODEC(LZ4), "
        "`tx_size` UInt32 COMMENT 'type' CODEC(T64, LZ4), "
        "`date` UInt32 COMMENT 'date' CODEC(T64, LZ4) "
        ") "
        "ENGINE = ReplacingMergeTree "
        "PARTITION BY(shard_id, date) "
        "ORDER BY(pool_index,height) "
        "SETTINGS index_granularity = 8192;";
    client_.Execute(create_cmd);
    return true;
}

bool ClickHouseClient::CreateAccountTable() {
    std::string create_cmd = std::string("CREATE TABLE if not exists ") + kClickhouseAccountTableName + " ( "
        "`id` String COMMENT 'prehash' CODEC(LZ4), "
        "`shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4), "
        "`pool_index` UInt32 COMMENT 'pool_index' CODEC(T64, LZ4), "
        "`balance` UInt64 COMMENT 'balance' CODEC(T64, LZ4) "
        ") "
        "ENGINE = ReplacingMergeTree "
        "PARTITION BY(shard_id) "
        "ORDER BY(id,pool_index,height) "
        "SETTINGS index_granularity = 8192;";
    client_.Execute(create_cmd);
    return true;
}

bool ClickHouseClient::CreateAccountKeyValueTable() {
    std::string create_cmd = std::string("CREATE TABLE if not exists ") + kClickhouseAccountKvTableName + " ( "
        "`id` String COMMENT 'prehash' CODEC(LZ4), "
        "`shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4), "
        "`key` String COMMENT 'key' CODEC(LZ4), "
        "`value` String COMMENT 'value' CODEC(LZ4) "
        ") "
        "ENGINE = ReplacingMergeTree "
        "PARTITION BY(shard_id) "
        "ORDER BY(id) "
        "SETTINGS index_granularity = 8192;";
    client_.Execute(create_cmd);
    return true;
}

bool ClickHouseClient::CreateTable() try {
    CreateTransactionTable();
    CreateBlockTable();
    CreateAccountTable();
    CreateAccountKeyValueTable();
    return true;
} catch (std::exception& e) {
    TENON_ERROR("add new block failed[%s]", e.what());
    printf("add new block failed[%s]", e.what());
    return false;
}

void ClickHouseClient::CheckBlockFinished() {

}

};  // namespace ck

};  // namespace tenon
