#include "stdafx.h"
#include "transport/processor.h"

namespace tenon {

namespace transport {

Processor* Processor::Instance() {
    static Processor ins;
    return &ins;
}

void Processor::RegisterProcessor(uint32_t type, MessageProcessor processor) {
    assert(type < common::kLegoMaxMessageTypeCount);
//    assert(message_processor_[type] == nullptr);
    message_processor_[type] = processor;
}

void Processor::UnRegisterProcessor(uint32_t type) {
    assert(type < common::kLegoMaxMessageTypeCount);
    message_processor_[type] = nullptr;
}

void Processor::HandleMessage(TransportMessagePtr& message) {
    assert(message->type() < common::kLegoMaxMessageTypeCount);
    if (message_processor_[message->type()] == nullptr) {
        message_processor_[common::kRelayMessage](message);
        return;
    }

    assert(message_processor_[message->type()] != nullptr);
    message_processor_[message->type()](message);
}

Processor::Processor() {
    for (uint32_t i = 0; i < common::kLegoMaxMessageTypeCount; ++i) {
        message_processor_[i] = nullptr;
    }
}

Processor::~Processor() {}

}  // namespace transport

}  // namespace tenon
