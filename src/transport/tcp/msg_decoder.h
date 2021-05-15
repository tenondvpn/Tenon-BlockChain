#pragma once

#include <deque>

#include "tnet/utils/packet_decoder.h"
#include "transport/tcp/msg_packet.h"

namespace lego {

namespace transport {

class MsgDecoder: public tnet::PacketDecoder {
public:
    MsgDecoder();
    virtual ~MsgDecoder();
    virtual bool Decode(const char* buf, size_t len);
    virtual tnet::Packet* GetPacket();
    virtual void Free();

private:
    bool GetPacketLen(const char* buf, size_t len, size_t& pos);

    std::deque<MsgPacket*> packet_list_;
    std::string tmp_str_;
    uint32_t packet_len_{ 0 };
    uint32_t type_{ 0 };
};

}  // namespace transport

}  // namespace lego
