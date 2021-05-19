#include "stdafx.h"
#include "statistics/statistics.h"

#include "common/encode.h"
#include "common/string_utils.h"
#include "common/time_utils.h"
#include "block/account_manager.h"

namespace tenon {

namespace common {

template<>
uint64_t MinHeapUniqueVal(const tenon::statis::AccountBalance& val) {
    return common::Hash::Hash64(val.account_id);
}

}  // namespace common

}  // namespace tenon

namespace tenon {

namespace statis {

static const std::string kAddrCount = "kAddrCount";
static const std::string kTxCount = "kTxCount";
static const std::string kAllTxCount = "kAllTxCount";
static const std::string kTxAmount = "kTxAmount";
static const std::string kAllTxAmount = "kAllTxAmount";
static const std::string kAllLego = "kAllLego";
static const std::string kTps = "kTps";
static const std::string kActiveUser = "kActiveUser";
static const std::string kNewUser = "kNewUser";

bool operator<(AccountBalance& lhs, AccountBalance& rhs) {
    return lhs.balance < rhs.balance;
}

bool operator==(const AccountBalance& lhs, const AccountBalance& rhs) {
    return memcmp(lhs.account_id, rhs.account_id, sizeof(lhs.account_id)) == 0;
}

Statistics* Statistics::Instance() {
    static Statistics ins;
    return &ins;
}

Statistics::Statistics() : best_addr_queue_("best_addr") {
    statis_tick_.CutOff(kTpsUpdatePeriod, std::bind(&Statistics::StatisUpdate, this));
    period_begin_ = std::chrono::steady_clock::now();
    tps_get_begin_ = period_begin_;
    dict_key_ = db::kGlobalDbQueueStatistics + "_dict";
    get_addr_count();
    get_all_lego();
    tx_count();
    all_tx_count();
    tx_amount();
    all_tx_count();
}

Statistics::~Statistics() {}

void Statistics::inc_addr_count(uint32_t count, db::DbWriteBach& db_batch) {
    if (addr_count_ == 0) {
        get_addr_count();
    }

    addr_count_ += count;
    db::Dict::Instance()->Hset(dict_key_, kAddrCount, std::to_string(addr_count_), db_batch);
}

uint32_t Statistics::get_addr_count() {
    if (addr_count_ != 0) {
        return addr_count_;
    }

    std::string tmp_str;
    if (db::Dict::Instance()->Hget(dict_key_, kAddrCount, &tmp_str)) {
        addr_count_ = common::StringUtil::ToUint32(tmp_str);
    }

    return addr_count_;
}

void Statistics::inc_all_lego(
        const std::string& account_id,
        int64_t now_balance,
        int64_t pre_balance,
        db::DbWriteBach& db_batch) {
    if (all_acc_lego_ == 0) {
        get_all_lego();
    }

    if (now_balance != pre_balance) {
        all_acc_lego_ += (now_balance - pre_balance);
        db::Dict::Instance()->Hset(dict_key_, kAllLego, std::to_string(all_acc_lego_), db_batch);
    }

    if (now_balance < 100000) {
        return;
    }

    AccountBalance item;
    memcpy(item.account_id, account_id.c_str(), sizeof(item.account_id));
    item.balance = now_balance;
    std::lock_guard<std::mutex> gaurd(best_addr_queue_mutex_);
    best_addr_queue_.push(item, db_batch);
}

int64_t Statistics::get_all_lego() {
    if (all_acc_lego_ != 0) {
        return all_acc_lego_;
    }

    std::string tmp_str;
    if (db::Dict::Instance()->Hget(dict_key_, kAllLego, &tmp_str)) {
        all_acc_lego_ = common::StringUtil::ToInt64(tmp_str);
    }

    return all_acc_lego_;
}

void Statistics::inc_tx_count(uint32_t count, db::DbWriteBach& db_batch) {
    if (tx_count_ == 0) {
        tx_count();
    }

    if (all_tx_count_ == 0) {
        all_tx_count();
    }

    tx_count_ += count;
    all_tx_count_ += count;
    db::Dict::Instance()->Hset(dict_key_, kTxCount, std::to_string(tx_count_), db_batch);
    db::Dict::Instance()->Hset(dict_key_, kAllTxCount, std::to_string(all_tx_count_), db_batch);
}

uint32_t Statistics::tx_count() {
    if (tx_count_ !=0) {
        return tx_count_;
    }

    std::string tmp_str;
    if (db::Dict::Instance()->Hget(dict_key_, kTxCount, &tmp_str)) {
        tx_count_ = common::StringUtil::ToUint32(tmp_str);
    }

    return tx_count_;
}

uint32_t Statistics::all_tx_count() {
    if (all_tx_count_ != 0) {
        return all_tx_count_;
    }

    std::string tmp_str;
    if (db::Dict::Instance()->Hget(dict_key_, kAllTxCount, &tmp_str)) {
        all_tx_count_ = common::StringUtil::ToUint32(tmp_str);
    }

    return all_tx_count_;
}

void Statistics::inc_tx_amount(uint64_t amount, db::DbWriteBach& db_batch) {
    if (tx_amount_ == 0) {
        tx_amount();
    }

    if (all_tx_amount_ == 0) {
        all_tx_amount();
    }

    tx_amount_ += amount;
    all_tx_amount_ += amount;
    db::Dict::Instance()->Hset(dict_key_, kTxAmount, std::to_string(tx_amount_), db_batch);
    db::Dict::Instance()->Hset(dict_key_, kAllTxAmount, std::to_string(all_tx_amount_), db_batch);
}

uint64_t Statistics::tx_amount() {
    if (tx_amount_ != 0) {
        return tx_amount_;
    }

    std::string tmp_str;
    if (db::Dict::Instance()->Hget(dict_key_, kTxAmount, &tmp_str)) {
        tx_amount_ = common::StringUtil::ToUint64(tmp_str);
    }

    return tx_amount_;
}

uint64_t Statistics::all_tx_amount() {
    if (all_tx_amount_ != 0) {
        return all_tx_amount_;
    }

    std::string tmp_str;
    if (db::Dict::Instance()->Hget(dict_key_, kAllTxAmount, &tmp_str)) {
        all_tx_amount_ = common::StringUtil::ToUint64(tmp_str);
    }

    return all_tx_amount_;
}

float Statistics::tps() {
    return tps_;
}

void Statistics::inc_active_user_count(
        uint64_t tm_ms,
        const std::string& account_id,
        db::DbWriteBach& db_batch) {
    uint64_t month_tm = tm_ms / (60llu * 60llu * 1000llu * 24llu * 30);
    std::string month_key = kActiveUser + "_" + std::to_string(month_tm);
    uint32_t month_active_count = 0;
    db::UniqueQueue* uniq_queue = nullptr;
    {
        std::lock_guard<std::mutex> guard(active_uniq_map_mutex_);
        auto iter = active_uniq_map_.find(month_tm);
        if (iter == active_uniq_map_.end()) {
            uniq_queue = new db::UniqueQueue(
                    db::kGlobalDbQueueStatistics + "_auq_" + std::to_string(month_tm),
                    (std::numeric_limits<uint32_t>::max)());
            active_uniq_map_[month_tm] = uniq_queue;
        } else {
            uniq_queue = iter->second;
        }
    }

    if (uniq_queue->push(account_id, db_batch)) {
        {
            std::lock_guard<std::mutex> guard(active_user_map_mutex_);
            auto day_iter = active_user_map_.find(month_tm);
            if (day_iter == active_user_map_.end()) {
                std::string tmp_str;
                if (db::Dict::Instance()->Hget(dict_key_, month_key, &tmp_str)) {
                    active_user_map_[month_tm] = common::StringUtil::ToUint32(tmp_str) + 1;
                } else {
                    active_user_map_[month_tm] = 1;
                }
            } else {
                active_user_map_[month_tm] += 1;
            }

            month_active_count = active_user_map_[month_tm];
        }

        db::Dict::Instance()->Hset(
                dict_key_,
                month_key,
                std::to_string(month_active_count),
                db_batch);
    }

    uint64_t day_tm = tm_ms / (60llu * 60llu * 1000llu * 24llu);
    std::string day_key = kActiveUser + "_" + std::to_string(day_tm);
    uint32_t day_active_count = 0;
    uniq_queue = nullptr;
    {
        std::lock_guard<std::mutex> guard(active_uniq_map_mutex_);
        auto iter = active_uniq_map_.find(day_tm);
        if (iter == active_uniq_map_.end()) {
            uniq_queue = new db::UniqueQueue(
                    db::kGlobalDbQueueStatistics + "_auq_" + std::to_string(day_tm),
                    (std::numeric_limits<uint32_t>::max)());
            active_uniq_map_[day_tm] = uniq_queue;
        } else {
            uniq_queue = iter->second;
        }
    }

    if (uniq_queue->push(account_id, db_batch)) {
        {
            std::lock_guard<std::mutex> guard(active_user_map_mutex_);
            auto day_iter = active_user_map_.find(day_tm);
            if (day_iter == active_user_map_.end()) {
                std::string tmp_str;
                if (db::Dict::Instance()->Hget(dict_key_, day_key, &tmp_str)) {
                    active_user_map_[day_tm] = common::StringUtil::ToUint32(tmp_str) + 1;
                } else {
                    active_user_map_[day_tm] = 1;
                }
            } else {
                active_user_map_[day_tm] += 1;
            }

            day_active_count = active_user_map_[day_tm];
        }

        db::Dict::Instance()->Hset(dict_key_, day_key, std::to_string(day_active_count), db_batch);
    }

    uint64_t hour_tm = tm_ms / (60llu * 60llu * 1000llu);
    std::string hour_key = kActiveUser + "_" + std::to_string(hour_tm);
    uint32_t hour_active_count = 0;
    {
        std::lock_guard<std::mutex> guard(active_uniq_map_mutex_);
        auto iter = active_uniq_map_.find(hour_tm);
        if (iter == active_uniq_map_.end()) {
            uniq_queue = new db::UniqueQueue(
                    db::kGlobalDbQueueStatistics + "_auq_" + std::to_string(hour_tm),
                    (std::numeric_limits<uint32_t>::max)());
            active_uniq_map_[hour_tm] = uniq_queue;
        } else {
            uniq_queue = iter->second;
        }
    }

    if (uniq_queue->push(account_id, db_batch)) {
        {
            std::lock_guard<std::mutex> guard(active_user_map_mutex_);
            auto hour_iter = active_user_map_.find(hour_tm);
            if (hour_iter == active_user_map_.end()) {
                std::string tmp_str;
                if (db::Dict::Instance()->Hget(dict_key_, hour_key, &tmp_str)) {
                    active_user_map_[hour_tm] = common::StringUtil::ToUint32(tmp_str) + 1;
                } else {
                    active_user_map_[hour_tm] = 1;
                }
            } else {
                active_user_map_[hour_tm] += 1;
            }

            hour_active_count = active_user_map_[hour_tm];
        }

        db::Dict::Instance()->Hset(
                dict_key_,
                hour_key,
                std::to_string(hour_active_count),
                db_batch);
    }
}

std::deque<uint32_t> Statistics::active_user_count(int32_t type, uint32_t count) {
    if (type == 0) {
        return ActiveUserCountForMonth(count);
    } else if (type == 1) {
        return ActiveUserCountForDay(count);
    } else if (type == 2) {
        return ActiveUserCountForHour(count);
    }

    return std::deque<uint32_t>();
}

std::deque<uint32_t> Statistics::ActiveUserCountForMonth(uint32_t count) {
    std::deque<uint32_t> tmp_queue;
    uint32_t now_month_tm = common::TimeUtils::TimestampDays() / 30;
    for (uint32_t i = now_month_tm - count; i <= now_month_tm; ++i) {
        std::string day_key = kActiveUser + "_" + std::to_string(i);
        std::lock_guard<std::mutex> guard(active_user_map_mutex_);
        auto day_iter = active_user_map_.find(i);
        if (day_iter == active_user_map_.end()) {
            std::string tmp_str;
            if (db::Dict::Instance()->Hget(dict_key_, day_key, &tmp_str)) {
                active_user_map_[i] = common::StringUtil::ToUint32(tmp_str);
            } else {
                active_user_map_[i] = 0;
            }
        }

        tmp_queue.push_back(active_user_map_[i]);
    }

    return tmp_queue;
}

std::deque<uint32_t> Statistics::ActiveUserCountForDay(uint32_t count) {
    std::deque<uint32_t> tmp_queue;
    uint32_t now_day_tm = common::TimeUtils::TimestampDays();
    for (uint32_t i = now_day_tm - count; i <= now_day_tm; ++i) {
        std::string day_key = kActiveUser + "_" + std::to_string(i);
        std::lock_guard<std::mutex> guard(active_user_map_mutex_);
        auto day_iter = active_user_map_.find(i);
        if (day_iter == active_user_map_.end()) {
            std::string tmp_str;
            if (db::Dict::Instance()->Hget(dict_key_, day_key, &tmp_str)) {
                active_user_map_[i] = common::StringUtil::ToUint32(tmp_str);
            } else {
                active_user_map_[i] = 0;
            }
        }

        tmp_queue.push_back(active_user_map_[i]);
    }

    return tmp_queue;
}

std::deque<uint32_t> Statistics::ActiveUserCountForHour(uint32_t count) {
    std::deque<uint32_t> tmp_queue;
    uint32_t now_hour_tm = common::TimeUtils::TimestampHours();
    for (uint32_t i = now_hour_tm - count; i <= now_hour_tm; ++i) {
        std::string hour_key = kActiveUser + "_" + std::to_string(i);
        std::lock_guard<std::mutex> guard(active_user_map_mutex_);
        auto day_iter = active_user_map_.find(i);
        if (day_iter == active_user_map_.end()) {
            std::string tmp_str;
            if (db::Dict::Instance()->Hget(dict_key_, hour_key, &tmp_str)) {
                active_user_map_[i] = common::StringUtil::ToUint32(tmp_str);
            } else {
                active_user_map_[i] = 0;
            }
        }

        tmp_queue.push_back(active_user_map_[i]);
    }

    return tmp_queue;
}

std::deque<float> Statistics::tps_queue() {
    auto now_tm = std::chrono::steady_clock::now();
    auto period_tick = tps_get_begin_ + std::chrono::seconds(10);
    if (period_tick < now_tm) {
        std::lock_guard<std::mutex> guard(tmp_tps_queue_mutex_);
        return tmp_tps_queue_;
    }

    std::deque<float> tmp_queue;
    uint32_t size = tps_queue_.size();
    for (uint32_t i = 0; i < size; ++i) {
        std::string tmp_val;
        tps_queue_.get(i, &tmp_val);
        tmp_queue.push_back(common::StringUtil::ToFloat(tmp_val));
    }

    std::lock_guard<std::mutex> guard(tmp_tps_queue_mutex_);
    tmp_tps_queue_.swap(tmp_queue);
    tps_get_begin_ = now_tm;
    return tmp_tps_queue_;
}

std::deque<uint32_t> Statistics::tx_count_q() {
    auto now_tm = std::chrono::steady_clock::now();
    auto period_tick = txcount_get_begin_ + std::chrono::seconds(10);
    if (period_tick < now_tm) {
        std::lock_guard<std::mutex> guard(tmp_txcount_queue_mutex_);
        return tmp_txcount_queue_;
    }

    std::deque<uint32_t> tmp_queue;
    uint32_t size = tx_count_q_.size();
    for (uint32_t i = 0; i < size; ++i) {
        std::string tmp_val;
        tx_count_q_.get(i, &tmp_val);
        tmp_queue.push_back(common::StringUtil::ToUint32(tmp_val));
    }

    std::lock_guard<std::mutex> guard(tmp_txcount_queue_mutex_);
    tmp_txcount_queue_.swap(tmp_queue);
    txcount_get_begin_ = now_tm;
    return tmp_txcount_queue_;
}

std::deque<uint64_t> Statistics::tx_amount_q() {
    auto now_tm = std::chrono::steady_clock::now();
    auto period_tick = txamount_get_begin_ + std::chrono::seconds(10);
    if (period_tick < now_tm) {
        std::lock_guard<std::mutex> guard(tmp_txamount_queue_mutex_);
        return tmp_txamount_queue_;
    }

    std::deque<uint64_t> tmp_queue;
    uint32_t qsize = tx_amount_q_.size();
    for (uint32_t i = 0; i < qsize; ++i) {
        std::string tmp_val;
        tx_amount_q_.get(i, &tmp_val);
        tmp_queue.push_back(common::StringUtil::ToUint64(tmp_val));
    }

    std::lock_guard<std::mutex> guard(tmp_txamount_queue_mutex_);
    tmp_txamount_queue_.swap(tmp_queue);
    txamount_get_begin_ = now_tm;
    return tmp_txamount_queue_;
}

void Statistics::inc_period_tx_count(uint32_t count) {
    period_tx_count_ += count;
}

void Statistics::StatisUpdate() {
    tps_ = (float)period_tx_count_ / ((float)kTpsUpdatePeriod / (1000.0f * 1000.0f));
    tps_queue_.push(std::to_string(tps_));
    period_tx_count_ = 0;
    auto tick_now = std::chrono::steady_clock::now();
    auto period_tick = period_begin_ + std::chrono::minutes(60);
    if (tick_now >= period_tick) {
        period_begin_ = tick_now;
        tx_count_q_.push(std::to_string(tx_count_));
        tx_count_ = 0;
        tx_amount_q_.push(std::to_string(tx_amount_));
        tx_amount_ = 0;
    }

    statis_tick_.CutOff(kTpsUpdatePeriod, std::bind(&Statistics::StatisUpdate, this));
}

void Statistics::GetBestAddr(nlohmann::json& res_json) {
    std::deque<std::string> tmp_queue;
    common::MinHeap<AccountBalance, 128> best_addrs(false);
    auto datas = best_addr_queue_.mem_data();
    for (uint32_t i = 0; i < best_addr_queue_.size(); ++i) {
        best_addrs.push(datas[i]);
    }

    int index = 0;
    while (!best_addrs.empty()) {
        std::string id(best_addrs.top().account_id, sizeof(best_addrs.top().account_id));
        res_json[index]["id"] = common::Encode::HexEncode(id);
        res_json[index]["balance"] = best_addrs.top().balance;
        res_json[index]["ratio"] = (double)best_addrs.top().balance / (double)all_acc_lego_;
        ++index;
        best_addrs.pop();
    }
}

std::deque<std::string> Statistics::best_addrs() {
    std::deque<std::string> tmp_queue;
    common::MinHeap<AccountBalance, 128> best_addrs(false);
    auto datas = best_addr_queue_.mem_data();
    for (uint32_t i = 0; i < best_addr_queue_.size(); ++i) {
        best_addrs.push(datas[i]);
    }

    while (!best_addrs.empty()) {
        std::string id(best_addrs.top().account_id, sizeof(best_addrs.top().account_id));
        std::string item = common::Encode::HexEncode(id) +
                ":" + std::to_string(best_addrs.top().balance);
        tmp_queue.push_back(item);
        best_addrs.pop();
    }

    return tmp_queue;
}

void Statistics::inc_new_user_count(
        uint64_t tm_ms,
        const std::string& account_id,
        db::DbWriteBach& db_batch) {
    uint64_t day_tm = tm_ms / (60llu * 60llu * 1000llu * 24llu);
    std::string day_key = kNewUser + "_" + std::to_string(day_tm);
    uint32_t day_new_count = 0;
    db::UniqueQueue* uniq_queue = nullptr;
    {
        std::lock_guard<std::mutex> guard(new_uniq_map_mutex_);
        auto iter = new_uniq_map_.find(day_tm);
        if (iter == new_uniq_map_.end()) {
            uniq_queue = new db::UniqueQueue(
                    db::kGlobalDbQueueStatistics + "_nuq_" + std::to_string(day_tm),
                    (std::numeric_limits<uint32_t>::max)());
            new_uniq_map_[day_tm] = uniq_queue;
        } else {
            uniq_queue = iter->second;
        }
    }

    if (uniq_queue->push(account_id, db_batch)) {
        {
            std::lock_guard<std::mutex> guard(new_user_map_mutex_);
            auto day_iter = new_user_map_.find(day_tm);
            if (day_iter == new_user_map_.end()) {
                std::string tmp_str;
                if (db::Dict::Instance()->Hget(dict_key_, day_key, &tmp_str)) {
                    new_user_map_[day_tm] = common::StringUtil::ToUint32(tmp_str) + 1;
                } else {
                    new_user_map_[day_tm] = 1;
                }
            } else {
                new_user_map_[day_tm] += 1;
            }

            day_new_count = new_user_map_[day_tm];
        }

        db::Dict::Instance()->Hset(dict_key_, day_key, std::to_string(day_new_count), db_batch);
    }

    uint64_t hour_tm = tm_ms / (60llu * 60llu * 1000llu);
    std::string hour_key = kNewUser + "_" + std::to_string(hour_tm);
    uint32_t hour_new_count = 0;
    {
        std::lock_guard<std::mutex> guard(new_uniq_map_mutex_);
        auto iter = new_uniq_map_.find(hour_tm);
        if (iter == new_uniq_map_.end()) {
            uniq_queue = new db::UniqueQueue(
                    db::kGlobalDbQueueStatistics + "_nuq_" + std::to_string(hour_tm),
                    (std::numeric_limits<uint32_t>::max)());
            new_uniq_map_[hour_tm] = uniq_queue;
        } else {
            uniq_queue = iter->second;
        }
    }

    if (uniq_queue->push(account_id, db_batch)) {
        {
            std::lock_guard<std::mutex> guard(new_user_map_mutex_);
            auto hour_iter = new_user_map_.find(hour_tm);
            if (hour_iter == new_user_map_.end()) {
                std::string tmp_str;
                if (db::Dict::Instance()->Hget(dict_key_, hour_key, &tmp_str)) {
                    new_user_map_[hour_tm] = common::StringUtil::ToUint32(tmp_str) + 1;
                } else {
                    new_user_map_[hour_tm] = 1;
                }
            } else {
                new_user_map_[hour_tm] += 1;
            }

            hour_new_count = new_user_map_[hour_tm];
        }

        db::Dict::Instance()->Hset(dict_key_, hour_key, std::to_string(hour_new_count), db_batch);
    }
}

std::deque<uint32_t> Statistics::new_user_count(bool for_day, uint32_t count) {
    if (for_day) {
        return NewUserCountForDay(count);
    }

    return NewUserCountForHour(count);
}

std::deque<uint32_t> Statistics::NewUserCountForDay(uint32_t count) {
    std::deque<uint32_t> tmp_queue;
    uint32_t now_day_tm = common::TimeUtils::TimestampDays();
    for (uint32_t i = now_day_tm - count; i <= now_day_tm; ++i) {
        std::string day_key = kNewUser + "_" + std::to_string(i);
        std::lock_guard<std::mutex> guard(new_user_map_mutex_);
        auto day_iter = new_user_map_.find(i);
        if (day_iter == new_user_map_.end()) {
            std::string tmp_str;
            if (db::Dict::Instance()->Hget(dict_key_, day_key, &tmp_str)) {
                new_user_map_[i] = common::StringUtil::ToUint32(tmp_str);
            } else {
                new_user_map_[i] = 0;
            }
        }

        tmp_queue.push_back(new_user_map_[i]);
    }

    return tmp_queue;
}

std::deque<uint32_t> Statistics::NewUserCountForHour(uint32_t count) {
    std::deque<uint32_t> tmp_queue;
    uint32_t now_hour_tm = common::TimeUtils::TimestampHours();
    for (uint32_t i = now_hour_tm - count; i <= now_hour_tm; ++i) {
        std::string hour_key = kNewUser + "_" + std::to_string(i);
        std::lock_guard<std::mutex> guard(new_user_map_mutex_);
        auto day_iter = new_user_map_.find(i);
        if (day_iter == new_user_map_.end()) {
            std::string tmp_str;
            if (db::Dict::Instance()->Hget(dict_key_, hour_key, &tmp_str)) {
                new_user_map_[i] = common::StringUtil::ToUint32(tmp_str);
            } else {
                new_user_map_[i] = 0;
            }
        }

        tmp_queue.push_back(new_user_map_[i]);
    }

    return tmp_queue;
}

}  // namespace statis

}  // namespace tenon
