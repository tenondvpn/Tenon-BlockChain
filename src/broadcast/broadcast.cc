#include "stdafx.h"
#include "broadcast/broadcast.h"

#include "common/utils.h"
#include "common/global_info.h"
#include "common/hash.h"
#include "dht/base_dht.h"
#include "broadcast/broadcast_utils.h"

namespace tenon {

namespace broadcast {

Broadcast::Broadcast() {}

Broadcast::~Broadcast() {}

bool Broadcast::TestForEvilNode(float evil_rate) {
    static bool evil_tag = 0;
    if (evil_tag == 0) {
        static std::mutex tmp_mutex;
        std::lock_guard<std::mutex> guard(tmp_mutex);
        if (evil_tag == 0) {
            uint32_t hash_num = static_cast<uint32_t>(common::GlobalInfo::Instance()->id_hash());
            srand(hash_num);
            int32_t rand_num = rand() % 10000;
            if (rand_num <= static_cast<int32_t>(evil_rate * 10000)) {
                evil_tag = 1;
            } else {
                evil_tag = 2;
            }
        }
    }
    return evil_tag == 1;
}

void Broadcast::Send(
    dht::BaseDhtPtr& dht_ptr,
    const transport::protobuf::Header& message,
    const std::vector<dht::NodePtr>& nodes) {
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        transport::MultiThreadHandler::Instance()->tcp_transport()->Send(
                nodes[i]->public_ip(),
                nodes[i]->local_port + 1,
                0,
                message);
    }
}

}  // namespace broadcast

}  // namespace tenon
