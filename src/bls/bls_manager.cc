#include "bls/bls_manager.h"

namespace tenon {

namespace bls {

BlsManager* BlsManager::Instance() {
    static BlsManager ins;
    return &ins;
}

void BlsManager::ProcessNewElectBlock(
        elect::protobuf::ElectBlock& elect_block,
        elect::MembersPtr& new_members) {
    std::lock_guard<std::mutex> guard(mutex_);
    waiting_bls_ = std::make_shared<bls::BlsDkg>();
    waiting_bls_->OnNewElectionBlock(elect_block.elect_height(), new_members);
}

int BlsManager::Sign(
        const std::string& sign_msg,
        std::string* sign) {
    return kBlsSuccess;
}

int BlsManager::Verify(
        const std::string& sign,
        const std::string& sign_msg) {
    return kBlsSuccess;
}

BlsManager::BlsManager() {}

BlsManager::~BlsManager() {}

};  // namespace bls

};  // namespace tenon
