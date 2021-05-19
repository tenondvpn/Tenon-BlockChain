#pragma once

#include "tnet/utils/packet_factory.h"
#include "transport/tcp/msg_encoder.h"
#include "transport/tcp/msg_decoder.h"

namespace tenon {

namespace transport {

class EncoderFactory : public tnet::PacketFactory {
public:
    virtual tnet::PacketEncoder* CreateEncoder() {
        return new MsgEncoder();
    }

    virtual tnet::PacketDecoder* CreateDecoder() {
        return new MsgDecoder();
    }

    EncoderFactory() {}
    virtual ~EncoderFactory() {}

};

}  // namespace transport

}  // namespace tenon
