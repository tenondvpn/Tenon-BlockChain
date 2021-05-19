#include "stdafx.h"
#include "services/account_with_secret.h"

namespace tenon {

namespace service {

AccountWithSecret* AccountWithSecret::Instance() {
    static AccountWithSecret ins;
    return &ins;
}

PeerInfo* AccountWithSecret::GetPeerInfo(const std::string& pubkey) {
    std::lock_guard<std::mutex> guard(pubkey_sec_map_mutex_);
    auto iter = pubkey_sec_map_.find(pubkey);
    if (iter != pubkey_sec_map_.end()) {
        return iter->second;
    }
    return nullptr;
}

PeerInfo* AccountWithSecret::NewPeer(const std::string& pubkey, const std::string& method) {
    std::lock_guard<std::mutex> guard(pubkey_sec_map_mutex_);
    auto iter = pubkey_sec_map_.find(pubkey);
    if (iter != pubkey_sec_map_.end()) {
        iter->second->timeout = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kPeerTimeout));
        return iter->second;
    }
    auto peer_ptr = new PeerInfo(pubkey, method);
    if (!peer_ptr->init()) {
        return nullptr;
    }
    pubkey_sec_map_[pubkey] = peer_ptr;
    return peer_ptr;
}

void AccountWithSecret::CheckPeerTimeout() {
    {
        auto now_time = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> guard(pubkey_sec_map_mutex_);
        for (auto iter = pubkey_sec_map_.begin(); iter != pubkey_sec_map_.end();) {
            if (iter->second->timeout <= now_time) {
                delete iter->second;
                pubkey_sec_map_.erase(iter++);
            } else {
                ++iter;
            }
        }
    }
    tick_.CutOff(kCheckTimeoutPeriod, std::bind(&AccountWithSecret::CheckPeerTimeout, this));
}

AccountWithSecret::AccountWithSecret() {
//     tick_.CutOff(kCheckTimeoutPeriod, std::bind(&AccountWithSecret::CheckPeerTimeout, this));
}

AccountWithSecret::~AccountWithSecret() {}

}  // namespace service

}  // namespace tenon
