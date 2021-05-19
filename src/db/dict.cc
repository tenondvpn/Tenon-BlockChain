#include "stdafx.h"
#include "db/dict.h"

#include "common/utils.h"
#include "common/log.h"
#include "db/db_utils.h"

namespace tenon {

namespace db {

Dict* Dict::Instance() {
    static Dict ins;
    return &ins;
}

// bool Dict::Hset(const std::string& key, const std::string& field, const std::string& value) {
//     std::string db_key = key + kDbFieldLinkLetter + field;
//     auto st = Db::Instance()->Put(db_key, value);
//     if (!st.ok()) {
//         TENON_ERROR("dict put key: [%s] value: [%s] failed! error[%s]",
//             db_key.c_str(), value.c_str(), st.ToString().c_str());
//         return false;
//     }
// 
//     return true;
// }

bool Dict::Hset(
        const std::string& key,
        const std::string& field,
        const std::string& value,
        db::DbWriteBach& db_batch) {
    std::string db_key = key + kDbFieldLinkLetter + field;
    db_batch.Put(db_key, value);
    return true;
}


bool Dict::Hget(const std::string& key, const std::string& field, std::string* value) {
    std::string db_key = key + kDbFieldLinkLetter + field;
    auto st = Db::Instance()->Get(db_key, value);
    if (!st.ok()) {
//         TENON_ERROR("dict put key: [%s] failed! error[%s]",
//             db_key.c_str(), st.ToString().c_str());
        return false;
    }

    return true;
}

bool Dict::Hdel(const std::string& key, const std::string& field) {
    std::string db_key = key + kDbFieldLinkLetter + field;
    auto st = Db::Instance()->Delete(db_key);
    if (!st.ok()) {
        TENON_ERROR("dict put key: [%s] failed! error[%s]",
            db_key.c_str(), st.ToString().c_str());
        return false;
    }

    return true;
}

}  // namespace db

}  // namespace tenon
