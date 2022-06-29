ATTACH TABLE _ UUID 'df11f435-b589-4bba-b0bd-55b5c42090b8'
(
    `time` UInt64 COMMENT 'time' CODEC(LZ4),
    `all_tenon` UInt64 COMMENT 'tenon' CODEC(LZ4),
    `all_address` UInt32 COMMENT 'address' CODEC(T64, LZ4),
    `all_contracts` UInt32 COMMENT 'contracts' CODEC(T64, LZ4),
    `all_transactions` UInt32 COMMENT 'transactions' CODEC(LZ4),
    `all_nodes` UInt32 COMMENT 'nodes' CODEC(LZ4),
    `all_waiting_nodes` UInt32 COMMENT 'waiting_nodes' CODEC(LZ4),
    `date` UInt32 COMMENT 'date' CODEC(T64, LZ4)
)
ENGINE = ReplacingMergeTree
PARTITION BY date
ORDER BY time
SETTINGS index_granularity = 8192
