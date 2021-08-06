#pragma once

#include "bls/proto/bls.pb.h"
#include "common/utils.h"
#include "election/elect_node_detail.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace bls {

class Dkg {
public:
    static Dkg* Instance();
    void OnNewElectionBlock(elect::MembersPtr& members);

private:
    Dkg();
    ~Dkg();
    void HandleMessage(const transport::TransportMessagePtr& header);
    void HandleVerifyBroadcast(
        const transport::TransportMessagePtr& header,
        const protobuf::BlsMessage& bls_msg);

    DISALLOW_COPY_AND_ASSIGN(Dkg);
};

};  // namespace bls

};  // namespace tenon
