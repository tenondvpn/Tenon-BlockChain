#pragma once

#include <unordered_map>

#include "common/utils.h"
#include "common/thread_safe_queue.h"
#include "common/tick.h"
#include "common/user_property_key_define.h"
#include "common/time_utils.h"
#include "db/db.h"
#include "db/db_unique_queue.h"
#include "db/dict.h"
#include "init/update_vpn_init.h"

namespace lego {

namespace service {

struct BandwidthInfo {
    static const uint32_t kMaxBandwidthFreeUse = 2048u * 1024u * 1024u;

    BandwidthInfo(uint32_t up, uint32_t down, const std::string& acc_id, const std::string& plat)
            : up_bandwidth(up), down_bandwidth(down), account_id(acc_id) {
        timeout = std::chrono::steady_clock::now();
        client_staking_time = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(1ll * 1000ll * 1000ll));
        pre_bandwidth_get_time = std::chrono::steady_clock::now();
        pre_payfor_get_time = std::chrono::steady_clock::now();
        if (plat == "ios") {
            client_platform = lego::common::kIos;
        }

        if (plat == "and") {
            client_platform = lego::common::kAndroid;
        }

        if (plat == "win") {
            client_platform = lego::common::kWindows;
        }

        if (plat == "mac") {
            client_platform = lego::common::kMac;
        }
        today_used_bandwidth = 0;
    }

    bool Valid() {
        return true;
        if (vip_timestamp == -100) {
            return true;
        }

        if (IsVip()) {
            if (today_used_bandwidth <= lego::init::UpdateVpnInit::Instance()->max_vip_bandwidth()) {
                return true;
            }
            return false;
        }

        if (today_used_bandwidth <= lego::init::UpdateVpnInit::Instance()->max_free_bandwidth()) {
            return true;
        }
        return false;
    }

    bool ValidRoute() {
        if (vip_timestamp == -100) {
            return true;
        }

        if (IsVip()) {
            return true;
        }

        return false;
    }


    bool IsVip() {
        uint32_t now_day_timestamp = lego::common::TimeUtils::TimestampDays();
        int32_t vip_days = vip_payed_tenon / lego::common::kVpnVipMinPayfor;
        if (vip_days > 0 && ((vip_timestamp + vip_days + 1) >= now_day_timestamp)) {
            return true;
        }
        return false;
    }

    volatile uint32_t up_bandwidth{ 0 };
    volatile uint32_t down_bandwidth{ 0 };
    uint64_t today_used_bandwidth;
    std::chrono::steady_clock::time_point timeout;
    std::chrono::steady_clock::time_point client_staking_time;
    int32_t vip_timestamp{ -100 };
    uint64_t vip_payed_tenon{ 0 };
    std::string account_id;
    std::chrono::steady_clock::time_point join_time;
    std::chrono::steady_clock::time_point pre_bandwidth_get_time;
    std::chrono::steady_clock::time_point pre_payfor_get_time;
    uint64_t vpn_login_height{ 0 };
    uint64_t vpn_pay_for_height{ 0 };
    uint32_t client_platform{ lego::common::kUnknown };
};

typedef std::shared_ptr<BandwidthInfo> BandwidthInfoPtr;

class BandwidthManager {
public:
    static BandwidthManager* Instance();
    void AddServerBandwidth(int32_t bandwidth);
    void AddRouteBandwidth(int32_t bandwidth);
    void AddClientBandwidthInfo(BandwidthInfoPtr& client_bandwith);

private:
    BandwidthManager();
    ~BandwidthManager();
    void FlushToDb();
    void CheckAccountValid(db::DbWriteBach& db_batch);
    void CheckServerBandwidth(db::DbWriteBach& db_batch);
    void CheckRouteBandwidth(db::DbWriteBach& db_batch);
    void BandwidthProv(db::DbWriteBach& db_batch);
    void BftForLocalNodePassedBandwidth();

    static const uint32_t kFlushDbPeriod = 10000000u;

    common::ThreadSafeQueue<int32_t> server_bandwidth_queue_;
    common::ThreadSafeQueue<int32_t> route_bandwidth_queue_;
    common::ThreadSafeQueue<BandwidthInfoPtr> bandwidth_queue_;
    db::UniqueQueue user_day_unique_queue_{ "dulbq", 10000000 };
    std::unordered_map<std::string, BandwidthInfoPtr> user_bandwidth_map_;
    common::Tick flush_to_db_tick_;
    uint64_t svr_bandwidth_all_{ 0 };
    uint64_t route_bandwidth_all_{ 0 };
    uint64_t prev_flush_to_bft_tm_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(BandwidthManager);
};

}  // namespace service

}  // namespace lego