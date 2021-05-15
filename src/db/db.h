#pragma once

#include <mutex>
#include <memory>
#include "common/utils.h"

#ifdef LEVELDB
#include "leveldb/options.h"
#include "leveldb/slice.h"
#include "leveldb/status.h"
#include "leveldb/write_batch.h"
#include "leveldb/cache.h"
#include "leveldb/filter_policy.h"
#include "leveldb/db.h"
#else
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/status.h"
#include "rocksdb/write_batch.h"
#include "rocksdb/filter_policy.h"
#include "rocksdb/db.h"
#endif

namespace lego {

namespace db {

#ifdef LEVELDB
    typedef leveldb::WriteBatch DbWriteBach;
    typedef leveldb::Status DbStatus;
    typedef leveldb::DB DickDb;
    typedef leveldb::WriteOptions DbWriteOptions;
    typedef leveldb::ReadOptions DbReadOptions;
    typedef leveldb::Slice DbSlice;
    typedef leveldb::Iterator DbIterator;
#else
    typedef rocksdb::WriteBatch DbWriteBach;
    typedef rocksdb::Status DbStatus;
    typedef rocksdb::DB DickDb;
    typedef rocksdb::WriteOptions DbWriteOptions;
    typedef rocksdb::ReadOptions DbReadOptions;
    typedef rocksdb::Slice DbSlice;
    typedef rocksdb::Iterator DbIterator;
#endif // LEVELDB

class Db {
public:
    static Db* Instance();
    bool Init(const std::string& db_path);
    bool Exist(const std::string& key) {
        DbIterator* it = db_->NewIterator(DbReadOptions());
        it->Seek(key);
        bool res = false;
        if (it->Valid() && it->key().ToString() == key) {
            res = true;
        }

        delete it;
        return res;
    }

    DbStatus Put(DbWriteBach& db_batch) {
        DbWriteOptions write_opt;
        return db_->Write(write_opt, &db_batch);
    }

    DbStatus Put(const std::string& key, const std::string& value) {
        DbWriteOptions write_opt;
        return db_->Put(write_opt, DbSlice(key), DbSlice(value));
    }

    DbStatus Get(const std::string& key, std::string* value) {
        DbReadOptions read_opt;
        return db_->Get(read_opt, DbSlice(key), value);
    }

    std::vector<DbStatus> Get(const std::vector<DbSlice>& keys, std::vector<std::string>* value) {
        DbReadOptions read_opt;
        return std::vector<DbStatus>();
//         return db_->MultiGet(read_opt, keys, value);
    }

    DbStatus Delete(const std::string& key) {
        DbWriteOptions write_opt;
        return db_->Delete(write_opt, DbSlice(key));
    }

    std::shared_ptr<DickDb>& db() {
        return db_;
    }

    std::shared_ptr<DickDb> db_;

private:
    Db();
    ~Db();
    Db(const Db&);
    Db(const Db&&);
    Db& operator=(const Db&);

    bool inited_{ false };
    std::mutex mutex;
};

}  // db

}  // lego
