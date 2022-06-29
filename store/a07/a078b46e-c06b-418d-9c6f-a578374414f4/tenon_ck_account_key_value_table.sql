ATTACH TABLE _ UUID '314c7fd6-c1a4-417e-8e7d-63457e1f46d3'
(
    `from` String COMMENT 'prehash' CODEC(LZ4),
    `to` String COMMENT 'prehash' CODEC(LZ4),
    `type` UInt32 COMMENT 'type' CODEC(T64, LZ4),
    `shard_id` UInt32 COMMENT 'shard_id' CODEC(T64, LZ4),
    `key` String COMMENT 'key' CODEC(LZ4),
    `value` String COMMENT 'value' CODEC(LZ4)
)
ENGINE = ReplacingMergeTree
PARTITION BY shard_id
ORDER BY (type, key, from, to)
SETTINGS index_granularity = 8192
