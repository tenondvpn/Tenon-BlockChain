ATTACH TABLE _ UUID 'fde0b8d2-3da1-4b43-b9d7-bfd5d1cd09b1'
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
    `tx_size` UInt32 COMMENT 'type' CODEC(T64, LZ4),
    `date` UInt32 COMMENT 'date' CODEC(T64, LZ4)
)
ENGINE = ReplacingMergeTree
PARTITION BY (shard_id, date)
ORDER BY (pool_index, height)
SETTINGS index_granularity = 8192
