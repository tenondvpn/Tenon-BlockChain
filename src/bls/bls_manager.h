#pragma once

#include <memory>
#include <unordered_map>

#include "bls/bls_dkg.h"
#include "bls/bls_utils.h"
#include "election/proto/elect.pb.h"

namespace tenon {

namespace bls {

class BlsManager {
public:
    static BlsManager* Instance();
    void ProcessNewElectBlock(
        bool this_node_elected,
        uint32_t network_id,
        uint64_t elect_height,
        elect::MembersPtr& new_members);
    void SetUsedElectionBlock(
        uint64_t elect_height,
        uint32_t network_id,
        uint32_t member_count,
        const libff::alt_bn128_G2& common_public_key);
    int Sign(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_Fr& local_sec_key,
        const std::string& sign_msg,
        std::string* sign_x,
        std::string* sign_y);
    int Sign(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const std::string& sign_msg,
        libff::alt_bn128_G1* bn_sign);
    int Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const libff::alt_bn128_G1& sign,
        const std::string& sign_msg);
    void AddBlsConsensusInfo(elect::protobuf::ElectBlock& ec_block);

    libff::alt_bn128_Fr local_sec_key() {
        if (used_bls_ == nullptr) {
            return libff::alt_bn128_Fr::zero();
        }

        return used_bls_->local_sec_key();
    }

private:
    BlsManager();
    ~BlsManager();
    void HandleMessage(const transport::TransportMessagePtr& header);
    void HandleFinish(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg);
    bool IsSignValid(
        const elect::MembersPtr& members,
        const protobuf::BlsMessage& bls_msg,
        std::string* content_to_hash);

    std::shared_ptr<bls::BlsDkg> used_bls_{ nullptr };
    std::shared_ptr<bls::BlsDkg> waiting_bls_{ nullptr };
    uint64_t max_height_{ common::kInvalidUint64 };
    std::mutex mutex_;
    std::mutex sign_mutex_;
    std::unordered_map<uint32_t, BlsFinishItemPtr> finish_networks_map_;
    std::mutex finish_networks_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(BlsManager);
};


};  // namespace bls

};  // namespace tenon
