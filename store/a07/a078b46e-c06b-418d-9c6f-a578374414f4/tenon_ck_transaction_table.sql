ATTACH TABLE _ UUID 'b0eb3544-7e33-44e5-9219-f46556da1dc0'
(
    `shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4),
    `pool_index` UInt32 COMMENT 'pool_index' CODEC(T64, LZ4),
    `height` UInt64 COMMENT 'height' CODEC(T64, LZ4),
    `prehash` String COMMENT 'prehash' CODEC(LZ4),
    `hash` String COMMENT 'hash' CODEC(LZ4),
    `version` UInt32 COMMENT 'version' CODEC(LZ4),
    `vss` UInt64 COMMENT 'vss' CODEC(T64, LZ4),
    `elect_height` UInt64 COMMENT 'elect_height' CODEC(T64, LZ4),
    `bitmap` String COMMENT 'success consensers' CODEC(LZ4),
    `timestamp` UInt64 COMMENT 'timestamp' CODEC(T64, LZ4),
    `timeblock_height` UInt64 COMMENT 'timeblock_height' CODEC(T64, LZ4),
    `bls_agg_sign_x` String COMMENT 'bls_agg_sign_x' CODEC(LZ4),
    `bls_agg_sign_y` String COMMENT 'bls_agg_sign_y' CODEC(LZ4),
    `commit_bitmap` String COMMENT 'commit_bitmap' CODEC(LZ4),
    `gid` String COMMENT 'gid' CODEC(LZ4),
    `from` String COMMENT 'from' CODEC(LZ4),
    `from_pubkey` String COMMENT 'from_pubkey' CODEC(LZ4),
    `from_sign` String COMMENT 'from_sign' CODEC(LZ4),
    `to` String COMMENT 'to' CODEC(LZ4),
    `amount` UInt64 COMMENT 'amount' CODEC(T64, LZ4),
    `gas_limit` UInt64 COMMENT 'gas_limit' CODEC(T64, LZ4),
    `gas_used` UInt64 COMMENT 'gas_used' CODEC(T64, LZ4),
    `gas_price` UInt64 COMMENT 'gas_price' CODEC(T64, LZ4),
    `balance` UInt64 COMMENT 'balance' CODEC(T64, LZ4),
    `to_add` UInt32 COMMENT 'to_add' CODEC(T64, LZ4),
    `type` UInt32 COMMENT 'type' CODEC(T64, LZ4),
    `attrs` String COMMENT 'attrs' CODEC(LZ4),
    `status` UInt32 COMMENT 'status' CODEC(T64, LZ4),
    `tx_hash` String COMMENT 'tx_hash' CODEC(LZ4),
    `call_contract_step` UInt32 COMMENT 'call_contract_step' CODEC(T64, LZ4),
    `storages` String COMMENT 'storages' CODEC(LZ4),
    `transfers` String COMMENT 'transfers' CODEC(LZ4),
    `date` UInt32 COMMENT 'date' CODEC(T64, LZ4)
)
ENGINE = ReplacingMergeTree
PARTITION BY (shard_id, date)
ORDER BY (pool_index, height, type, from, to)
SETTINGS index_granularity = 8192
