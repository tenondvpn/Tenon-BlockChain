#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

#include "common/spin_mutex.h"
#include "common/thread_safe_queue.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport.h"
#include "transport/transport_utils.h"

namespace tenon {

namespace transport {

class MessageHandler;
class MultiThreadHandler;

class ThreadHandler {
public:
    ThreadHandler(uint32_t thread_idx);
    ~ThreadHandler();
    void Join();

private:
    void HandleMessage();

    std::shared_ptr<std::thread> thread_{ nullptr };
    bool destroy_{ false };
    uint32_t thread_idx_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(ThreadHandler);
};

typedef std::shared_ptr<ThreadHandler> ThreadHandlerPtr;

class MultiThreadHandler {
public:
    static MultiThreadHandler* Instance();
    void Init(TransportPtr& transport_ptr, TransportPtr& tcp_transport_ptr);
    void HandleMessage(
            const std::string& from_ip,
            uint16_t from_port,
            const char* message,
            uint32_t len,
            int32_t transport_type);
    void HandleMessage(const protobuf::Header& msg);
	void HandleRemoteMessage(
            const std::string& from_ip,
			uint16_t from_port,
			const char* buf,
			uint32_t len,
            int32_t transport_type);
	std::shared_ptr<protobuf::Header> GetMessageFromQueue(uint32_t thread_idx);
    void Destroy();
    void ResetTransport(TransportPtr& transport_ptr);
    void ResetTcpTransport(TransportPtr& transport_ptr);
    TransportPtr transport() {
        return transport_;
    }

    TransportPtr tcp_transport() {
        return tcp_transport_;
    }

private:
    MultiThreadHandler();
    ~MultiThreadHandler();
    int HandleClientMessage(
            std::shared_ptr<transport::protobuf::Header>& msg_ptr,
            const std::string& from_ip,
            uint16_t from_port);
    void Join();

    static const int kQueueObjectCount = 1024 * 1024;

    std::queue<std::shared_ptr<protobuf::Header>> priority_queue_map_[kMessageHandlerThreadCount];
    std::queue<std::shared_ptr<protobuf::Header>> local_queue_;
//     common::ThreadSafeQueue<std::shared_ptr<protobuf::Header>, kQueueObjectCount> priority_queue_map_[kMessageHandlerThreadCount];
//     common::ThreadSafeQueue<std::shared_ptr<protobuf::Header>, kQueueObjectCount> local_queue_;
//     common::SpinMutex local_queue_mutex_;
//     std::map<uint32_t, common::ThreadSafeQueue<std::shared_ptr<protobuf::Header>, kQueueObjectCount>> priority_queue_map_;
    std::mutex priority_queue_map_mutex_;
    std::vector<ThreadHandlerPtr> thread_vec_;
    bool inited_{ false };
    std::mutex inited_mutex_;
    TransportPtr transport_{ nullptr };
    TransportPtr tcp_transport_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(MultiThreadHandler);
};

}  // namespace transport

}  // namespace tenon
