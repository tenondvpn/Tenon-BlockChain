#pragma once

#include <unordered_map>
#include <mutex>

#include "services/vpn_server/server.h"

namespace tenon {

namespace service {

class AccountWithSecret {
public:
    static AccountWithSecret* Instance();
    PeerInfo* NewPeer(const std::string& pubkey, const std::string& method);
    PeerInfo* GetPeerInfo(const std::string& pubkey);

private:
    AccountWithSecret();
    ~AccountWithSecret();
    void CheckPeerTimeout();

    static const uint32_t kCheckTimeoutPeriod = 30 * 1000 * 1000;

    std::unordered_map<std::string, PeerInfo*> pubkey_sec_map_;
    std::mutex pubkey_sec_map_mutex_;
    common::Tick tick_;

    DISALLOW_COPY_AND_ASSIGN(AccountWithSecret);
};

}  // namespace service

}  // namespace tenon
