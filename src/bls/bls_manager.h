#pragma once

#include <memory>

#include "bls/bls_dkg.h"
#include "bls/bls_utils.h"
#include "election/proto/elect.pb.h"

namespace tenon {

namespace bls {

class BlsManager {
public:
    static BlsManager* Instance();
    void ProcessNewElectBlock(
        elect::protobuf::ElectBlock& elect_block,
        elect::MembersPtr& new_members);
    int Sign(
        const std::string& sign_msg,
        std::string* sign);
    int Verify(
        const std::string& sign,
        const std::string& sign_msg);

private:
    BlsManager();
    ~BlsManager();

    std::shared_ptr<bls::BlsDkg> used_bls_{ nullptr };
    std::shared_ptr<bls::BlsDkg> waiting_bls_{ nullptr };
    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(BlsManager);
};


};  // namespace bls

};  // namespace tenon
