#pragma once

#include <atomic>
#include <memory>
#include <random>
#include <unordered_map>

#include <bls/BLSPrivateKey.h>
#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSutils.h>
#include <dkg/dkg.h>

#include "bls/proto/bls.pb.h"
#include "bls/bls_utils.h"
#include "common/utils.h"
#include "common/tick.h"
#include "common/bitmap.h"
#include "dht/dht_utils.h"
#include "election/elect_node_detail.h"
#include "transport/transport_utils.h"
#include "transport/proto/transport.pb.h"

namespace tenon {

namespace bls {

class BlsDkg {
public:
    BlsDkg();
    ~BlsDkg();
    void OnNewElectionBlock(
        uint64_t elect_height,
        elect::MembersPtr& members);

    void SetInitElectionBlock(
            uint32_t t,
            uint32_t n,
            const libff::alt_bn128_Fr& local_sec_key,
            const libff::alt_bn128_G2 local_publick_key,
            const libff::alt_bn128_G2 common_public_key) {
        min_aggree_member_count_ = t;
        member_count_ = n;
        local_sec_key_ = local_sec_key_;
        local_publick_key_ = local_publick_key;
        common_public_key_ = common_public_key;
    }

    uint64_t elect_hegiht() {
        return elect_hegiht_;
    }

    const libff::alt_bn128_Fr& local_sec_key() const {
        return local_sec_key_;
    }

    const libff::alt_bn128_G2& local_publick_key() const {
        return local_publick_key_;
    }
    const libff::alt_bn128_G2& common_public_key() const {
        return common_public_key_;
    }

    uint32_t t() const {
        return min_aggree_member_count_;
    }

    uint32_t n() const {
        return member_count_;
    }

private:
    void HandleMessage(const transport::TransportMessagePtr& header);
    void HandleVerifyBroadcast(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg);
    void HandleVerifyBroadcastRes(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg);
    void HandleSwapSecKey(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg);
    void HandleAgainstParticipant(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg);
    void HandleFinish(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg);
    bool IsSignValid(const protobuf::BlsMessage& bls_msg, std::string* msg_hash);
    void BroadcastVerfify();
    void SwapSecKey();
    void Finish();
    void CreateContribution();
    void CreateDkgMessage(
        const dht::NodePtr& local_node,
        protobuf::BlsMessage& bls_msg,
        const std::string& message_hash,
        transport::protobuf::Header& msg);
    void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);
    void DumpContribution();
    void DumpLocalPrivateKey();
    void SendVerifyBrdResponse(const std::string& from_ip, uint16_t from_port);
    void BroadcastFinish(const common::Bitmap& bitmap);

    static const int64_t kDkgPeriodUs = common::kTimeBlockCreatePeriodSeconds / 2 * 1000u * 1000u;
    static const int64_t kDkgOffsetUs = kDkgPeriodUs / 10;
    static const int64_t kDkgWorkPeriodUs = (kDkgPeriodUs - 2 * kDkgOffsetUs) / 3;
    static const int64_t kDkgVerifyBrdBeginUs = kDkgOffsetUs;
    static const int64_t kDkgSwapSecKeyBeginUs = kDkgWorkPeriodUs + kDkgOffsetUs;
    static const int64_t kDkgFinishBeginUs = kDkgSwapSecKeyBeginUs + kDkgWorkPeriodUs + kDkgOffsetUs;

    elect::MembersPtr members_{ nullptr };
    uint64_t elect_hegiht_{ 0 };
    common::Tick dkg_verify_brd_timer_;
    common::Tick dkg_swap_seckkey_timer_;
    common::Tick dkg_finish_timer_;
    std::vector<std::vector<libff::alt_bn128_Fr>> all_secret_key_contribution_;
    std::vector<libff::alt_bn128_Fr> local_src_secret_key_contribution_;
    std::vector<std::vector<libff::alt_bn128_G2>> all_verification_vector_;
    int64_t local_offset_us_{ 0 };
    uint32_t local_member_index_{ common::kInvalidUint32 };
    std::shared_ptr<signatures::Dkg> dkg_instance_;
    uint32_t invalid_node_map_[common::kEachShardMaxNodeCount];
    uint32_t min_aggree_member_count_{ 0 };
    uint32_t member_count_{ 0 };
    libff::alt_bn128_Fr local_sec_key_;
    libff::alt_bn128_G2 local_publick_key_;
    libff::alt_bn128_G2 common_public_key_;
    std::shared_ptr<std::mt19937> random_ptr_;
    bool finished_{ false };
    uint32_t valid_sec_key_count_{ 0 };
    std::unordered_map<std::string, std::shared_ptr<MaxBlsMemberItem>> max_bls_members_;
    std::string max_finish_hash_;
    uint32_t max_finish_count_{ 0 };
    std::mutex mutex_;

#ifdef TENON_UNITTEST
    transport::protobuf::Header ver_brd_msg_;
    std::vector<transport::protobuf::Header> sec_swap_msgs_;
    std::vector<transport::protobuf::Header> sec_against_msgs_;
#endif
    DISALLOW_COPY_AND_ASSIGN(BlsDkg);
};

};  // namespace bls

};  // namespace tenon
