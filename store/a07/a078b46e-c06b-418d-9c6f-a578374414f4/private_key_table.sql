ATTACH TABLE _ UUID 'eb3a90b9-64e8-4804-aded-36b4e792286e'
(
    `seckey` String COMMENT 'seckey' CODEC(LZ4),
    `ecn_prikey` String COMMENT 'ecn_prikey' CODEC(LZ4),
    `date` UInt32 COMMENT 'date' CODEC(T64, LZ4)
)
ENGINE = ReplacingMergeTree
PARTITION BY date
ORDER BY seckey
SETTINGS index_granularity = 8192
