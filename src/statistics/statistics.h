#pragma once

#include <atomic>
#include <deque>
#include <queue>

#include "httplib.h"
#include "common/tick.h"
#include "db/db_queue.h"
#include "db/db_pri_queue.h"
#include "db/db_unique_queue.h"
#include "block/block_utils.h"
#include "block/db_account_info.h"
#include "statistics/statis_utils.h"
#include "db/db_utils.h"

namespace lego {

namespace statis {

class Statistics {
public:
    static Statistics* Instance();
    void inc_addr_count(uint32_t count, db::DbWriteBach& db_batch);
    uint32_t get_addr_count();
    void inc_active_user_count(
            uint64_t tm_ms,
            const std::string& account_id,
            db::DbWriteBach& db_batch);
    std::deque<uint32_t> active_user_count(int32_t type, uint32_t count);
    void inc_tx_count(uint32_t count, db::DbWriteBach& db_batch);
    uint32_t tx_count();
    uint32_t all_tx_count();
    void inc_tx_amount(uint64_t amount, db::DbWriteBach& db_batch);
    uint64_t tx_amount();
    uint64_t all_tx_amount();
    void inc_all_lego(
            const std::string& account_id,
            int64_t now_balance,
            int64_t pre_balance,
            db::DbWriteBach& db_batch);
    int64_t get_all_lego();
    void inc_new_user_count(
            uint64_t tm_ms, const std::string& account_id,
            db::DbWriteBach& db_batch);
    std::deque<uint32_t> new_user_count(bool for_day, uint32_t count);
    float tps();
    std::deque<float> tps_queue();
    std::deque<uint32_t> tx_count_q();
    std::deque<uint64_t> tx_amount_q();
    void inc_period_tx_count(uint32_t count);
    void GetBestAddr(nlohmann::json& res_json);
    std::deque<std::string> best_addrs();

private:
    Statistics();
    ~Statistics();
    void StatisUpdate();
    std::deque<uint32_t> ActiveUserCountForMonth(uint32_t count);
    std::deque<uint32_t> ActiveUserCountForDay(uint32_t count);
    std::deque<uint32_t> ActiveUserCountForHour(uint32_t count);
    std::deque<uint32_t> NewUserCountForDay(uint32_t count);
    std::deque<uint32_t> NewUserCountForHour(uint32_t count);

    static const uint32_t kTpsUpdatePeriod = 10u * 1000u * 1000u;
    static const uint32_t kMaxQueueSize = 128u;
    static const uint32_t kQueuePeriod = 60u;  // 60 min

    std::atomic<uint32_t> tx_count_{ 0 };
    std::atomic<uint64_t> tx_amount_{ 0 };
    std::atomic<uint32_t> all_tx_count_{ 0 };
    std::atomic<uint64_t> all_tx_amount_{ 0 };
    std::atomic<uint32_t> period_tx_count_{ 0 };
    std::atomic<uint32_t> addr_count_{ 0 };
    std::atomic<int64_t> all_acc_lego_{ 0 };
    std::atomic<float> tps_{ common::kInvalidFloat };
    std::unordered_map<uint64_t, uint32_t> active_user_map_;
    std::mutex active_user_map_mutex_;
    std::unordered_map<uint64_t, db::UniqueQueue*> active_uniq_map_;
    std::mutex active_uniq_map_mutex_;
    std::unordered_map<uint64_t, uint32_t> new_user_map_;
    std::mutex new_user_map_mutex_;
    std::unordered_map<uint64_t, db::UniqueQueue*> new_uniq_map_;
    std::mutex new_uniq_map_mutex_;

    db::Queue tps_queue_{ db::kGlobalDbQueueStatistics + "_tps", kMaxQueueSize };
    db::Queue tx_count_q_{ db::kGlobalDbQueueStatistics + "_txc", kMaxQueueSize };
    db::Queue tx_amount_q_{ db::kGlobalDbQueueStatistics + "_txa", kMaxQueueSize };
    db::Queue addr_q_{ db::kGlobalDbQueueStatistics + "_adr", kMaxQueueSize };
//     db::UniqueQueue best_addr_q_{ db::kGlobalDbQueueStatistics + "_baq", 10000000 };

    std::string dict_key_;
    common::Tick statis_tick_;
    std::chrono::steady_clock::time_point period_begin_;
    std::deque<float> tmp_tps_queue_;
    std::mutex tmp_tps_queue_mutex_;
    std::chrono::steady_clock::time_point tps_get_begin_;
    std::deque<uint32_t> tmp_txcount_queue_;
    std::mutex tmp_txcount_queue_mutex_;
    std::chrono::steady_clock::time_point txcount_get_begin_;
    std::deque<uint64_t> tmp_txamount_queue_;
    std::mutex tmp_txamount_queue_mutex_;
    std::chrono::steady_clock::time_point txamount_get_begin_;
    std::deque<uint32_t> tmp_addr_queue_;
    std::mutex tmp_addr_queue_mutex_;
    std::chrono::steady_clock::time_point addr_get_begin_;
    db::DbPriQueue<AccountBalance, 1024> best_addr_queue_;
    std::mutex best_addr_queue_mutex_;

    DISALLOW_COPY_AND_ASSIGN(Statistics);
};

}  // namespace statis

}  // namespace lego
