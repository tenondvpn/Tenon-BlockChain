ATTACH TABLE _ UUID '7342cdd3-195a-4b68-9122-2c57d7dfbfed'
(
    `id` String COMMENT 'prehash' CODEC(LZ4),
    `shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4),
    `pool_index` UInt32 COMMENT 'pool_index' CODEC(T64, LZ4),
    `balance` UInt64 COMMENT 'balance' CODEC(T64, LZ4)
)
ENGINE = ReplacingMergeTree
PARTITION BY shard_id
ORDER BY (id, pool_index)
SETTINGS index_granularity = 8192
