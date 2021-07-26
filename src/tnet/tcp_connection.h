#pragma once

#include <vector>

#include "common/tick.h"
#include "tnet/tnet_utils.h"
#include "tnet/socket/socket.h"
#include "tnet/event/event_loop.h"
#include "tnet/utils/bytes_buffer.h"
#include "tnet/utils/packet_decoder.h"
#include "tnet/utils/packet_encoder.h"

namespace tenon {

namespace tnet {

class TcpConnection :public EventHandler {
public:
    enum TcpState : int32_t {
        kTcpNone,
        kTcpConnecting,
        kTcpConnected,
        kTcpClosed
    };

    enum Action {
        kActionNone,
        kActionClose
    };

    TcpConnection(EventLoop& event_loop);
    virtual ~TcpConnection();
    void SetPacketEncoder(PacketEncoder* encoder);
    void SetPacketDecoder(PacketDecoder* decoder);
    void SetPacketHandler(const PacketHandler& handler);
    uint64_t GetBytesRecv() const;
    uint64_t GetBytesSend() const;
    void Destroy(bool closeSocketImmediately);
    virtual bool SendPacket(Packet& packet);
    virtual bool SendPacketWithoutLock(Packet& packet);
    virtual bool Connect(uint32_t timeout);
    virtual void Close();
    virtual void CloseWithoutLock();
    void SetTcpState(TcpState state) {
        tcp_state_ = state;
    }

    int32_t GetTcpState() {
        return tcp_state_;
    }

    void SetAction(int action) {
        action_ = action;
    }

    std::mutex& GetMutex() const {
        return mutex_;
    }

    EventLoop& GetEventLoop() const {
        return event_loop_;
    }

    Socket* GetSocket() const {
        return socket_;
    }

    void SetSocket(Socket& socket) {
        socket_ = &socket;
    }

    const std::string& ip() const {
        return ip_;
    }

    uint16_t port() const {
        return port_;
    }

    uint32_t id() {
        return id_;
    }

    void set_id(uint32_t id) {
        id_ = id;
    }

    uint64_t free_timeout_ms() {
        return free_timeout_ms_;
    }

private:
    typedef std::deque<ByteBufferPtr> BufferList;
    typedef BufferList::const_iterator BufferListConstIter;
    typedef BufferList::iterator BufferListIter;
    typedef std::vector<WriteableHandler> WriteableHandlerList;
    typedef WriteableHandlerList::const_iterator WriteableHandlerListConstIter;
    typedef WriteableHandlerList::iterator WriteableHandlerListIter;

    void NotifyWriteable(bool needRelease, bool inLock);
    void ActionAfterPacketSent();
    virtual bool OnRead();
    virtual void OnWrite();
    bool ConnectWithoutLock(uint32_t timeout);
    bool ProcessConnecting();
    void OnConnectTimeout();
    void NotifyCmdPacketAndClose(int type);
    void ReleaseByIOThread();

    mutable std::mutex mutex_;
    BufferList out_buffer_list_;
    WriteableHandlerList writeable_handle_list_;
    volatile TcpState tcp_state_{ kTcpNone };
    int action_{ 0 };
    EventLoop& event_loop_;
    Socket* socket_{ nullptr };
    PacketEncoder* packet_encoder_{ nullptr };
    PacketDecoder* packet_decoder_{ nullptr };
    std::atomic<int64_t> bytes_recv_{ 0 };
    std::atomic<int64_t> bytes_sent_{ 0 };
    PacketHandler packet_handler_;
    std::atomic<int16_t> destroy_flag_{ 0 };
    common::Tick connect_timeout_tick_;
    std::string ip_;
    uint16_t port_{ 0 };
    uint32_t id_{ 0 };
    uint64_t free_timeout_ms_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(TcpConnection);
};

}  // namespace tnet

}  // namespace tenon
