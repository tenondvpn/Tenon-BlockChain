#include "stdafx.h"
#include "transport/multi_thread.h"

#include "common/utils.h"
#include "common/global_info.h"
#include "common/time_utils.h"
#include "transport/transport_utils.h"
#include "transport/processor.h"
#include "transport/message_filter.h"
#include "transport/client_relay.h"
#include "transport/rudp/session_manager.h"

#ifdef ENABLE_CLIENT_MODE
#include "dht/base_dht.h"  // in-appropriate
#include "dht/dht_key.h"
#include "dht/proto/dht.pb.h"
#include "network/universal_manager.h"  // in-appropriate
#include "network/dht_manager.h"  // in-appropriate
#include "block/proto/block.pb.h"
#endif

namespace tenon {

namespace transport {

ThreadHandler::ThreadHandler(uint32_t thread_idx) : thread_idx_(thread_idx) {
    thread_.reset(new std::thread(&ThreadHandler::HandleMessage, this));
}

ThreadHandler::~ThreadHandler() {}

void ThreadHandler::Join() {
    destroy_ = true;
    if (thread_) {
        thread_->join();
        thread_ = nullptr;
    }
}

void ThreadHandler::HandleMessage() {
    while (!common::global_stop) {
        while (!common::global_stop) {
            auto msg_ptr = MultiThreadHandler::Instance()->GetMessageFromQueue(thread_idx_);
            if (!msg_ptr) {
                break;
            }

            msg_ptr->set_hop_count(msg_ptr->hop_count() + 1);
            auto btime = common::TimeUtils::TimestampUs();
            Processor::Instance()->HandleMessage(msg_ptr);
//             if (!msg_ptr->debug().empty()) {
//                 TRANSPORT_DEBUG("msg id: %lu, message coming: %s, has broadcast: %d, from: %s:%d, use time: %lu",
//                     msg_ptr->id(), msg_ptr->debug().c_str(), msg_ptr->has_broadcast(),
//                     msg_ptr->from_ip().c_str(), msg_ptr->from_port(),
//                     (common::TimeUtils::TimestampUs() - btime));
//             }
// 
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

MultiThreadHandler::MultiThreadHandler() {
    for (uint32_t i = 0; i < kMessageHandlerThreadCount; ++i) {
        priority_queue_map_[i] = std::queue<std::shared_ptr<protobuf::Header>>();
    }
}

MultiThreadHandler::~MultiThreadHandler() {
    Destroy();
}

MultiThreadHandler* MultiThreadHandler::Instance() {
    static MultiThreadHandler ins;
    return &ins;
}

void MultiThreadHandler::Init(
        TransportPtr& transport_ptr,
        TransportPtr& tcp_transport_ptr) {
    TRANSPORT_INFO("MultiThreadHandler::Init() ...");
    std::unique_lock<std::mutex> lock(inited_mutex_);
    if (inited_) {
        TRANSPORT_WARN("MultiThreadHandler::Init() before");
        return;
    }

    for (uint32_t i = 0; i < kMessageHandlerThreadCount; ++i) {
        thread_vec_.push_back(std::make_shared<ThreadHandler>(i));
    }
    transport_ = transport_ptr;
    tcp_transport_ = tcp_transport_ptr;
    inited_ = true;
    TRANSPORT_INFO("MultiThreadHandler::Init() success");
}

void MultiThreadHandler::ResetTransport(TransportPtr& transport_ptr) {
    transport_ = transport_ptr;
}

void MultiThreadHandler::ResetTcpTransport(TransportPtr& transport_ptr) {
    tcp_transport_ = transport_ptr;
}

void MultiThreadHandler::Destroy() {
    std::unique_lock<std::mutex> lock(inited_mutex_);
    for (uint32_t i = 0; i < thread_vec_.size(); ++i) {
        thread_vec_[i]->Join();
    }
    thread_vec_.clear();
    std::unique_lock<std::mutex> map_lock(priority_queue_map_mutex_);
    priority_queue_map_.clear();
    inited_ = false;
}

void MultiThreadHandler::HandleMessage(protobuf::Header& msg) {
    // just local message
    auto message_ptr = std::make_shared<transport::protobuf::Header>(msg);
    {
        std::unique_lock<std::mutex> lock(priority_queue_map_mutex_);
        uint32_t priority = kTransportPriorityLowest;
        if (message_ptr->has_priority() && (message_ptr->priority() < kTransportPriorityLowest)) {
            priority = message_ptr->priority();
        }
        priority_queue_map_[priority].push(message_ptr);
    }
}

void MultiThreadHandler::HandleMessage(
        void* tcp_conn,
        const std::string& from_ip,
        uint16_t from_port,
        const char* message,
        uint32_t len,
        int32_t transport_type) {
//     assert(len > sizeof(TransportHeader));
// 	TransportHeader* trans_header = (TransportHeader*)(message);
// 	if (trans_header->type == kKcpUdp) {
// 		SessionManager::Instance()->Recv(
// 				from_ip,
// 				from_port,
// 				message + sizeof(TransportHeader),
// 				len - sizeof(TransportHeader));
// 		return;
// 	}

    if (transport_type != kTcp) {
        HandleRemoteMessage(
                nullptr,
                from_ip,
                from_port,
                message + sizeof(TransportHeader),
                len - sizeof(TransportHeader),
                transport_type);
    } else {
        HandleRemoteMessage(
                tcp_conn,
                from_ip,
                from_port,
                message,
                len,
                transport_type);
    }
}

static std::unordered_map<uint32_t, uint32_t> type_count_map;
static std::mutex test_mutex;
static uint64_t b_time = 0;
void AddInMessage(uint32_t type) {
    auto now_tm = common::TimeUtils::TimestampMs();
    std::lock_guard<std::mutex> guard(test_mutex);
    ++type_count_map[type];
    if (now_tm - b_time > 10000) {
        b_time = now_tm;
        type_count_map.clear();
    }
}

void MultiThreadHandler::HandleRemoteMessage(
        void* tcp_conn,
		const std::string& from_ip,
		uint16_t from_port,
		const char* buf,
		uint32_t len,
        int32_t transport_type) {
	auto message_ptr = std::make_shared<transport::protobuf::Header>();
	if (!message_ptr->ParseFromArray(buf, len)) {
		TRANSPORT_ERROR("Message ParseFromString from string failed!"
            "[%s:%d][len: %d][transport_type: %d]",
            from_ip.c_str(), from_port, len, transport_type);
        return;
	}

#ifndef LEGO_TRACE_MESSAGE
    message_ptr->clear_debug();
#endif

    if (!common::GlobalInfo::Instance()->is_client() && message_ptr->client()) {
        if (!message_ptr->has_version()) {
            message_ptr->clear_debug();
#ifdef ENABLE_CLIENT_MODE
            if (message_ptr->type() == common::kBlockMessage) {
                block::protobuf::BlockMessage block_msg;
                if (!block_msg.ParseFromString(message_ptr->data())) {
                    return;
                }

                if (!block_msg.has_up_vpn_req()) {
                    return;
                }
            } else if (message_ptr->type() == common::kDhtMessage) {
                dht::protobuf::DhtMessage dht_msg;
                if (!dht_msg.ParseFromString(message_ptr->data())) {
                    return;
                }

                if (!dht_msg.has_bootstrap_req()) {
                    return;
                }
            } else {
                return;
            }
#endif
        }
    }

#ifdef ENABLE_CLIENT_MODE
    if (message_ptr->des_dht_key().size() != dht::kDhtKeySize) {
        return;
    }
#endif

    if (thread_vec_.empty()) {
		return;
	}

    assert(message_ptr->has_hash());
	if (message_ptr->hop_count() >= kMaxHops) {
		const auto& msg = *message_ptr;
		return;
	}

    if (message_ptr->has_broadcast()) {
		if (MessageFilter::Instance()->StopBroadcast(*message_ptr)) {
			return;
		}

		if (MessageFilter::Instance()->CheckUnique(message_ptr->hash())) {
// 			message_ptr->set_handled(true);
            return;
		} else {
			message_ptr->set_handled(false);
		}
// 	} else {
//         if (MessageFilter::Instance()->CheckUnique(message_ptr->hash())) {
// 			const auto& msg = *message_ptr;
// 			return;
// 		}
	}

    message_ptr->set_transport_type(transport_type);
    message_ptr->set_from_ip(from_ip);
    message_ptr->set_from_port(from_port);
    message_ptr->set_hop_count(message_ptr->hop_count() + 1);
    if (message_ptr->client()) {
		if (HandleClientMessage(message_ptr, from_ip, from_port) != kTransportSuccess) {
			return;
		}
	}

    if (common::GlobalInfo::Instance()->is_client()) {
        Processor::Instance()->HandleMessage(message_ptr);
        return;
    }


    {
		std::unique_lock<std::mutex> lock(priority_queue_map_mutex_);
		uint32_t priority = kTransportPriorityLowest;
		if (message_ptr->has_priority() &&
			    (message_ptr->priority() < kTransportPriorityLowest)) {
			priority = message_ptr->priority();
		}

        priority_queue_map_[priority].push(message_ptr);
        if (!message_ptr->debug().empty()) {
            TRANSPORT_DEBUG("msg id: %lu, message coming: %s, has broadcast: %d, from: %s:%d, priority: %d, size: %u",
                message_ptr->id(), message_ptr->debug().c_str(), message_ptr->has_broadcast(),
                from_ip.c_str(), from_port, priority, priority_queue_map_[priority].size());
        }
	}
}

int MultiThreadHandler::HandleClientMessage(
        std::shared_ptr<transport::protobuf::Header>& message_ptr,
        const std::string& from_ip,
        uint16_t from_port) {
#ifdef ENABLE_CLIENT_MODE
    if (!message_ptr->client_relayed()) {
        ClientRelay::Instance()->AddClient(
                message_ptr->src_dht_key(),
                from_ip,
                from_port,
                message_ptr->transport_type());
        dht::BaseDhtPtr dht = nullptr;
        uint32_t net_id = dht::DhtKeyManager::DhtKeyGetNetId(message_ptr->des_dht_key());
        if (message_ptr->universal()) {
            dht = network::UniversalManager::Instance()->GetUniversal(net_id);
        } else {
            dht = network::DhtManager::Instance()->GetDht(net_id);
        }

        if (dht == nullptr) {
            dht = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
        }

        if (dht == nullptr) {
            assert(dht != nullptr);
            return kTransportError;
        }

        message_ptr->set_client_dht_key(from_ip + "_" + std::to_string(from_port));
        message_ptr->set_src_dht_key(dht->local_node()->dht_key());
        message_ptr->set_client_relayed(true);
        message_ptr->set_client_proxy(true);
    } else {
        if (message_ptr->client_handled()) {
            auto client_node = ClientRelay::Instance()->GetClient(message_ptr->client_dht_key());
            if (client_node != nullptr) {
                message_ptr->set_des_dht_key(client_node->client_dht_key);
                auto& msg = *message_ptr;
                if (client_node->transport_type == transport::kTcp) {
                    tcp_transport_->Send(client_node->ip, client_node->port, 0, msg);
                }
                else {
                    transport_->Send(client_node->ip, client_node->port, 0, msg);
                }

                return kTransportClientSended;
            }
        }
    }
#endif
    return kTransportSuccess;
}

std::shared_ptr<protobuf::Header> MultiThreadHandler::GetMessageFromQueue(uint32_t thread_idx) {
    std::unique_lock<std::mutex> lock(priority_queue_map_mutex_);
    for (uint32_t i = kTransportPrioritySystem; i < kTransportPriorityMaxCount; ++i) {
        if (!priority_queue_map_[i].empty()) {
            std::shared_ptr<protobuf::Header> msg_obj = priority_queue_map_[i].front();
            priority_queue_map_[i].pop();
            return msg_obj;
        }
    }

    return nullptr;
}

void MultiThreadHandler::Join() {
    std::unique_lock<std::mutex> lock(inited_mutex_);
    if (!inited_) {
        return;
    }

    for (uint32_t i = 0; i < thread_vec_.size(); ++i) {
        thread_vec_[i]->Join();
    }
    thread_vec_.clear();
    inited_ = false;
}

}  // namespace transport

}  // namespace tenon
