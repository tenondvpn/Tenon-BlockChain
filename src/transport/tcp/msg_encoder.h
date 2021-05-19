#pragma once

#include "tnet/utils/bytes_buffer.h"
#include "tnet/utils/packet_encoder.h"
#include "transport/tcp/msg_packet.h"

namespace tenon {

namespace transport {

class MsgEncoder : public tnet::PacketEncoder {
public:
    MsgEncoder() {}

    virtual ~MsgEncoder() {}

    virtual bool Encode(const tnet::Packet& packet, tnet::ByteBuffer* buffer) {
#ifndef _WIN32
        MsgPacket* msg_packet = const_cast<MsgPacket*>(
                dynamic_cast<const MsgPacket*>(&packet));
        if (msg_packet == NULL) {
            return false;
        }

        char* data = nullptr;
        uint32_t len = 0;
        msg_packet->GetMessageEx(&data, &len);
        if (data == nullptr) {
            return false;
        }

        if (packet.EncodeType() == tnet::kEncodeWithHeader) {
            PacketHeader header(len, msg_packet->PacketType());
            buffer->Append((char*)&header, sizeof(header));
        }

        buffer->Append(data, len);
#endif // !_WIN
        return true;
    }

    virtual void Free() {
        delete this;
    }
};

}  // namespace transport

}  // namespace tenon
