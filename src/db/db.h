#pragma once

#include <mutex>
#include <memory>
#include "common/utils.h"
#include "dbsvr/ssdb/ssdb.h"
#include "dbsvr/util/bytes.h"

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

namespace tenon {

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
        if (it->Valid() && it->key().size() == key.size() &&
                memcmp(it->key().data(), key.c_str(), key.size()) == 0) {
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

    void ClearPrefix(const std::string& prefix) {
        DbReadOptions option;
        auto iter = db_->NewIterator(option);
        iter->Seek(prefix);
        int32_t valid_count = 0;
        while (iter->Valid()) {
            if (memcmp(prefix.c_str(), iter->key().data(), prefix.size()) != 0) {
                break;
            }

            DbWriteOptions write_opt;
            db_->Delete(write_opt, iter->key());
            ++valid_count;
            iter->Next();
        }

        delete iter;
    }

    virtual int zset(const Bytes &name, const Bytes &key, const Bytes &score, char log_type = BinlogType::SYNC) {
        return ssdb_->zset(name, key, score, log_type);
    }

    virtual int zdel(const Bytes &name, const Bytes &key, char log_type = BinlogType::SYNC) {
        return ssdb_->zdel(name, key, log_type);
    }

    virtual int zincr(const Bytes &name, const Bytes &key, int64_t by, int64_t *new_val, char log_type = BinlogType::SYNC) {
        return ssdb_->zincr(name, key, by, new_val, log_type);
    }

    virtual int64_t zsize(const Bytes &name) {
        return ssdb_->zsize(name);
    }

    virtual int zget(const Bytes &name, const Bytes &key, std::string *score) {
        return ssdb_->zget(name, key, score);
    }

    virtual int64_t zrank(const Bytes &name, const Bytes &key) {
        return ssdb_->zrank(name, key);
    }

    virtual int64_t zrrank(const Bytes &name, const Bytes &key) {
        return ssdb_->zrrank(name, key);
    }

    virtual ZIterator* zrange(const Bytes &name, uint64_t offset, uint64_t limit) {
        return ssdb_->zrange(name, offset, limit);
    }

    virtual ZIterator* zrrange(const Bytes &name, uint64_t offset, uint64_t limit) {
        return ssdb_->zrrange(name, offset, limit);
    }

    virtual ZIterator* zscan(const Bytes &name, const Bytes &key,
        const Bytes &score_start, const Bytes &score_end, uint64_t limit) {
        return ssdb_->zscan(name, key, score_start, score_end, limit);
    }

    virtual ZIterator* zrscan(const Bytes &name, const Bytes &key,
        const Bytes &score_start, const Bytes &score_end, uint64_t limit) {
        return ssdb_->zrscan(name, key, score_start, score_end, limit);
    }

    virtual int zlist(const Bytes &name_s, const Bytes &name_e, uint64_t limit,
        std::vector<std::string> *list) {
        return ssdb_->zlist(name_s, name_e, limit, list);
    }

    virtual int zrlist(const Bytes &name_s, const Bytes &name_e, uint64_t limit,
        std::vector<std::string> *list) {
        return ssdb_->zrlist(name_s, name_e, limit, list);
    }

    virtual int64_t zfix(const Bytes &name) {
        return ssdb_->zfix(name);
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
    SSDB* ssdb_{ nullptr };
    bool inited_{ false };
    std::mutex mutex;
};

}  // db

}  // tenon
