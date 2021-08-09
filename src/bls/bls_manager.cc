#include "bls/bls_manager.h"

namespace tenon {

namespace bls {

BlsManager* BlsManager::Instance() {
    static BlsManager ins;
    return &ins;
}

void BlsManager::ProcessNewElectBlock(
        uint64_t height,
        elect::protobuf::ElectBlock& elect_block) {

}

BlsManager::BlsManager() {}

BlsManager::~BlsManager() {}

};  // namespace bls

};  // namespace tenon
