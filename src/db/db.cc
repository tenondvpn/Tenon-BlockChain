#include "stdafx.h"
#include "db/db.h"

#include <iostream>

#include "common/utils.h"
#include "common/log.h"

namespace tenon {

namespace db {

Db::Db() {
}

Db::~Db() {
}

Db* Db::Instance() {
    static Db db;
    return &db;
}

#ifdef LEVELDB
bool Db::Init(const std::string& db_path) {
    if (inited_) {
        TENON_ERROR("storage db is inited![%s]", db_path.c_str());
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex);
    if (inited_) {
        TENON_ERROR("storage db is inited![%s]", db_path.c_str());
        return false;
    }

    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::DB* db = NULL;
    DbStatus status = leveldb::DB::Open(options, db_path, &db);
    if (!status.ok()) {
        TENON_ERROR("open db[%s] failed, error[%s]", db_path.c_str(), status.ToString().c_str());
        return false;
    }

    db_.reset(db);
    inited_ = true;
    return true;
}

#else

bool Db::Init(const std::string& db_path) {
    if (inited_) {
        TENON_ERROR("storage db is inited![%s]", db_path.c_str());
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex);
    if (inited_) {
        TENON_ERROR("storage db is inited![%s]", db_path.c_str());
        return false;
    }

    rocksdb::Options options;
    options.compaction_style = rocksdb::kCompactionStyleLevel;
    options.write_buffer_size = 67108864; // 64MB
    options.max_write_buffer_number = 3;
    options.target_file_size_base = 67108864; // 64MB
    options.max_background_compactions = 4;
    options.level0_file_num_compaction_trigger = 8;
    options.level0_slowdown_writes_trigger = 17;
    options.level0_stop_writes_trigger = 24;
    options.num_levels = 4;
    options.max_bytes_for_level_base = 536870912; // 512MB
    options.max_bytes_for_level_multiplier = 8;
    options.create_if_missing = true;
    options.keep_log_file_num = 1;
    options.max_open_files = 10;
    rocksdb::DB* db = NULL;
    rocksdb::Status status = rocksdb::DB::Open(options, db_path, &db);
    if (!status.ok()) {
        TENON_ERROR("open db[%s] failed, error[%s]", db_path.c_str(), status.ToString().c_str());
        return false;
    }

    db_.reset(db);
    inited_ = true;
    return true;
}

#endif

}  // db

}  // tenon
