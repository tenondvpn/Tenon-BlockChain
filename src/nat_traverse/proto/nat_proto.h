#pragma once

#include "common/utils.h"
#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/dht_utils.h"
#include "nat_traverse/proto/nat.pb.h"

namespace tenon {

namespace nat {

class NatProto {
public:
    static void CreateDetectionRequest(
            const dht::NodePtr& local_node,
            const dht::NodePtr& des_node,
            const std::string& peer_pubkey,
            dht::VerifySignCallback sign_cb,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key());
        msg.set_des_dht_key(des_node->dht_key());
        msg.set_priority(transport::kTransportPriorityHighest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kNatMessage);
        msg.set_client(local_node->client_mode);
        // TODO(tt): add sign
        nat::protobuf::NatMessage nat_msg;
        auto detection_req = nat_msg.mutable_detection_req();
        detection_req->set_public_ip(local_node->public_ip());
        detection_req->set_public_port(local_node->public_port);
        detection_req->set_local_ip(local_node->local_ip());
        detection_req->set_local_port(local_node->local_port);
        detection_req->set_id(local_node->id());
        detection_req->set_public_key(security::Schnorr::Instance()->str_pubkey());
        detection_req->set_nat_type(local_node->nat_type);
        detection_req->set_dht_key(local_node->dht_key());
        detection_req->set_client(local_node->client_mode);
        detection_req->set_min_svr_port(common::GlobalInfo::Instance()->min_svr_port());
        detection_req->set_max_svr_port(common::GlobalInfo::Instance()->max_svr_port());
        detection_req->set_min_route_port(common::GlobalInfo::Instance()->min_route_port());
        detection_req->set_max_route_port(common::GlobalInfo::Instance()->max_route_port());
        detection_req->set_min_udp_port(common::GlobalInfo::Instance()->min_udp_port());
        detection_req->set_max_udp_port(common::GlobalInfo::Instance()->max_udp_port());
        detection_req->set_node_weight(common::GlobalInfo::Instance()->node_weight());
        detection_req->set_node_tag(common::GlobalInfo::Instance()->node_tag());

        if (sign_cb != nullptr) {
            std::string enc_data;
            std::string sign_ch;
            std::string sign_re;
            if (sign_cb(peer_pubkey, "", &enc_data, &sign_ch, &sign_re) != dht::kDhtSuccess) {
                return;
            }

            nat_msg.set_enc_data(enc_data);
            nat_msg.set_sign_ch(sign_ch);
            nat_msg.set_sign_re(sign_re);
        }

        msg.set_data(nat_msg.SerializeAsString());
    }

private:
    NatProto() {}
    ~NatProto() {}

    DISALLOW_COPY_AND_ASSIGN(NatProto);
};

}  // namespace nat

}  // namespace tenon
