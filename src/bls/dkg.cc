#include "bls/dkg.h"

#include "network/route.h"

namespace tenon {

namespace bls {

Dkg* Dkg::Instance() {
    static Dkg ins;
    return &ins;
}

void Dkg::OnNewElectionBlock(elect::MembersPtr& members) {

}

Dkg::Dkg() {
    network::Route::Instance()->RegisterMessage(
        common::kBlsMessage,
        std::bind(&Dkg::HandleMessage, this, std::placeholders::_1));
}

Dkg::~Dkg() {}

void Dkg::HandleMessage(const transport::TransportMessagePtr& header_ptr) {
    auto& header = *header_ptr;
    assert(header.type() == common::kBlsMessage);
    // must verify message signature, to avoid evil node
    
}


};  // namespace bls

};  // namespace tenon
