#pragma once

#include <atomic>
#include <memory>

#include <bls/BLSPrivateKey.h>
#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSutils.h>
#include <dkg/dkg.h>

#include "bls/proto/bls.pb.h"
#include "common/utils.h"
#include "common/tick.h"
#include "dht/dht_utils.h"
#include "election/elect_node_detail.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace bls {

class Dkg {
public:
    Dkg();
    ~Dkg();
    void OnNewElectionBlock(uint64_t elect_height, elect::MembersPtr& members);

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
    bool IsSignValid(const protobuf::BlsMessage& bls_msg);
    void BroadcastVerfify();
    void SwapSecKey();
    void Finish();
    int CreateContribution();
    void CreateDkgMessage(
        const dht::NodePtr& local_node,
        protobuf::BlsMessage& bls_msg,
        const std::string& message_hash,
        transport::protobuf::Header& msg);
    void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);

    static const int64_t kDkgPeriodUs = common::kTimeBlockCreatePeriodSeconds / 2 * 1000u * 1000u;
    static const int64_t kDkgOffsetUs = kDkgPeriodUs / 10;
    static const int64_t kDkgWorkPeriodUs = (kDkgPeriodUs - kDkgOffsetUs) / 3;
    static const int64_t kDkgVerifyBrdBeginUs = kDkgOffsetUs;
    static const int64_t kDkgSwapSecKeyBeginUs =
        kDkgVerifyBrdBeginUs + kDkgWorkPeriodUs + kDkgOffsetUs;
    static const int64_t kDkgFinishBeginUs =
        kDkgSwapSecKeyBeginUs + kDkgWorkPeriodUs + kDkgOffsetUs;

    elect::MembersPtr members_{ nullptr };
    uint64_t elect_hegiht_{ 0 };
    common::Tick dkg_verify_brd_timer_;
    common::Tick dkg_swap_seckkey_timer_;
    common::Tick dkg_finish_timer_;
    std::vector<std::vector<libff::alt_bn128_Fr>> all_secret_key_contribution_;
    std::vector<std::vector<libff::alt_bn128_G2>> all_verification_vector_;
    int64_t local_offset_us_{ 0 };
    uint32_t local_member_index_{ common::kInvalidUint32 };
    std::shared_ptr<signatures::Dkg> dkg_instance_;
    uint32_t invalid_node_map_[common::kEachShardMaxNodeCount];
    uint32_t min_aggree_member_count_{ 0 };
    libff::alt_bn128_Fr local_sec_key_;
    std::vector<libff::alt_bn128_G2> public_keys_;
    libff::alt_bn128_G2 common_public_key_;
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(Dkg);
};

};  // namespace bls

};  // namespace tenon
