#pragma once

#include <atomic>

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
    static Dkg* Instance();
    void OnNewElectionBlock(uint64_t elect_height, elect::MembersPtr& members);

private:
    Dkg();
    ~Dkg();
    void HandleMessage(const transport::TransportMessagePtr& header);
    void HandleVerifyBroadcast(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg);
    void HandleSwapSecKey(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg);
    void HandleAgainstParticipant(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg);
    bool IsSignValid(const protobuf::BlsMessage& bls_msg);
    void BroadcastVerfify();
    void SwapSecKey();
    int CreateContribution();
    void CreateDkgMessage(
        const dht::NodePtr& local_node,
        protobuf::BlsMessage& bls_msg,
        const std::string& message_hash,
        transport::protobuf::Header& msg);
    void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param);

    elect::MembersPtr members_{ nullptr };
    uint64_t elect_hegiht_{ 0 };
    common::Tick dkg_timer_;
    std::vector<libff::alt_bn128_Fr> secret_key_contribution_;
    std::vector< libff::alt_bn128_G2 > verification_vector_;
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(Dkg);
};

};  // namespace bls

};  // namespace tenon
