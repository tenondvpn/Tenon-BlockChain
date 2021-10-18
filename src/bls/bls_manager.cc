#include "bls/bls_manager.h"

#include <dkg/dkg.h>
#include <libbls/bls/BLSPrivateKey.h>
#include <libbls/bls/BLSPrivateKeyShare.h>
#include <libbls/bls/BLSPublicKey.h>
#include <libbls/bls/BLSPublicKeyShare.h>
#include <libbls/tools/utils.h>
#include <libff/common/profiling.hpp>

#include "bls/bls_sign.h"
#include "common/db_key_prefix.h"
#include "db/db.h"
#include "election/elect_manager.h"
#include "init/init_utils.h"
#include "network/route.h"
#include "security/crypto.h"
#include "security/schnorr.h"
#include "security/secp256k1.h"

namespace tenon {

namespace bls {

void initLibSnark() noexcept {
    static bool s_initialized = []() noexcept
    {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
    (void)s_initialized;
}

BlsManager* BlsManager::Instance() {
    static BlsManager ins;
    return &ins;
}

void BlsManager::ProcessNewElectBlock(
        bool this_node_elected,
        uint32_t network_id,
        uint64_t elect_height,
        elect::MembersPtr& new_members) {
    {
        std::lock_guard<std::mutex> guard(finish_networks_map_mutex_);
        auto iter = finish_networks_map_.find(network_id);
        if (iter != finish_networks_map_.end()) {
            finish_networks_map_.erase(iter);
        }
    }

    if (!this_node_elected) {
        return;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    waiting_bls_ = std::make_shared<bls::BlsDkg>(
        0,
        0,
        libff::alt_bn128_Fr::zero(),
        libff::alt_bn128_G2::zero(),
        libff::alt_bn128_G2::zero());
    waiting_bls_->OnNewElectionBlock(elect_height, new_members);
}

void BlsManager::SetUsedElectionBlock(
        uint64_t elect_height,
        uint32_t network_id,
        uint32_t member_count,
        const libff::alt_bn128_G2& common_public_key) try {
    std::lock_guard<std::mutex> guard(mutex_);
    if (max_height_ != common::kInvalidUint64 && elect_height <= max_height_) {
        BLS_ERROR("elect_height error: %lu, %lu", elect_height, max_height_);
        return;
    }

    max_height_ = elect_height;
    std::string key = common::kBlsPrivateKeyPrefix +
        std::to_string(elect_height) + "_" +
        std::to_string(network_id) + "_" +
        common::GlobalInfo::Instance()->id();
    std::string val;
    auto st = db::Db::Instance()->Get(key, &val);
    if (!st.ok()) {
        BLS_ERROR("get bls private key failed![%s]", key.c_str());
        return;
    }

    std::string dec_data;
    if (elect_height <= 4) {
        // for genesis block with sure encrypt key
        if (security::Crypto::Instance()->GetDecryptData(
                init::kGenesisElectPrikeyEncryptKey,
                val,
                &dec_data) != security::kSecuritySuccess) {
            return;
        }
    } else {
        if (security::Crypto::Instance()->GetDecryptData(
                security::Schnorr::Instance()->str_prikey(),
                val,
                &dec_data) != security::kSecuritySuccess) {
            return;
        }
    }
    
    libff::alt_bn128_Fr local_sec_key = libff::alt_bn128_Fr(dec_data.c_str());
    auto t = common::GetSignerCount(member_count);
    crypto::Dkg dkg(t, member_count);
    libff::alt_bn128_G2 local_publick_key = dkg.GetPublicKeyFromSecretKey(local_sec_key);
    used_bls_ = std::make_shared<bls::BlsDkg>(
        t,
        member_count,
        local_sec_key,
        local_publick_key,
        common_public_key);
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
}

int BlsManager::Sign(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_Fr& local_sec_key,
        const std::string& sign_msg,
        libff::alt_bn128_G1* bn_sign) {
    if (used_bls_ == nullptr || used_bls_->n() == 0) {
        return kBlsError;
    }

    BlsSign::Sign(t, n, local_sec_key, sign_msg, bn_sign);
    return kBlsSuccess;
}

int BlsManager::Sign(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_Fr& local_sec_key,
        const std::string& sign_msg,
        std::string* sign_x,
        std::string* sign_y) try {
//     std::lock_guard<std::mutex> guard(sign_mutex_);
    if (used_bls_ == nullptr || used_bls_->n() == 0) {
        return kBlsError;
    }

    libff::alt_bn128_G1 bn_sign;
    BlsSign::Sign(t, n, local_sec_key, sign_msg, &bn_sign);
    bn_sign.to_affine_coordinates();
    *sign_x = crypto::ThresholdUtils::fieldElementToString(bn_sign.X);
    *sign_y = crypto::ThresholdUtils::fieldElementToString(bn_sign.Y);
    
//     BLSPublicKeyShare pkey(local_sec_key, t, n);
//     std::shared_ptr< std::vector< std::string > > strs = pkey.toString();
//     BFT_DEBUG("sign t: %u, , n: %u, , pk: %s,%s,%s,%s, sign x: %s, sign y: %s, sign msg: %s",
//         t, n, strs->at(0).c_str(), strs->at(1).c_str(),
//         strs->at(2).c_str(), strs->at(3).c_str(), (*sign_x).c_str(), (*sign_y).c_str(),
//         common::Encode::HexEncode(sign_msg).c_str());
//     std::cout << "sign t: " << used_bls_->t() << ", n: " << used_bls_->n()
//         << ", pk: " << strs->at(0) << ", " << strs->at(1) << ", " << strs->at(2) << ", " << strs->at(3)
//         << ", sign x: " << *sign_x
//         << ", sign y: " << *sign_y
//         << ", sign msg: " << common::Encode::HexEncode(sign_msg)
//         << std::endl;

    return kBlsSuccess;
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
    return kBlsError;
}

int BlsManager::Verify(
        uint32_t t,
        uint32_t n,
        const libff::alt_bn128_G2& pubkey,
        const libff::alt_bn128_G1& sign,
        const std::string& sign_msg) try {
    if (pubkey == libff::alt_bn128_G2::zero()) {
        return kBlsError;
    }

    //     std::lock_guard<std::mutex> guard(sign_mutex_);
    if (sign_msg.size() != 32) {
        BLS_ERROR("sign message error: %s", common::Encode::HexEncode(sign_msg));
        return kBlsError;
    }

//     auto sign_ptr = const_cast<libff::alt_bn128_G1*>(&sign);
//     sign_ptr->to_affine_coordinates();
//     auto sign_x = crypto::ThresholdUtils::fieldElementToString(sign_ptr->X);
//     auto sign_y = crypto::ThresholdUtils::fieldElementToString(sign_ptr->Y);
//     auto pk = const_cast<libff::alt_bn128_G2*>(&pubkey);
//     pk->to_affine_coordinates();
//     auto pk_ptr = std::make_shared<BLSPublicKey>(*pk);
//     auto strs = pk_ptr->toString();
//     BFT_DEBUG("verify t: %u, , n: %u, , pk: %s,%s,%s,%s, sign x: %s, sign y: %s, sign msg: %s",
//         t, n, strs->at(0).c_str(), strs->at(1).c_str(),
//         strs->at(2).c_str(), strs->at(3).c_str(), sign_x.c_str(), sign_y.c_str(),
//         common::Encode::HexEncode(sign_msg).c_str());

//     std::cout << "verify t: " << t << ", n: " << n
//         << ", pk: " << strs->at(0) << ", " << strs->at(1) << ", " << strs->at(2) << ", " << strs->at(3)
//         << ", sign x: " << sign_x
//         << ", sign y: " << sign_y
//         << ", sign msg: " << common::Encode::HexEncode(sign_msg)
//         << std::endl;
    return BlsSign::Verify(t, n, sign, sign_msg, pubkey);
} catch (std::exception& e) {
    BLS_ERROR("catch error: %s", e.what());
    return kBlsError;
}

void BlsManager::HandleMessage(const transport::TransportMessagePtr& header) {
    protobuf::BlsMessage bls_msg;
    if (!bls_msg.ParseFromString(header->data())) {
        BLS_ERROR("bls_msg.ParseFromString ParseFromString failed!");
        return;
    }

    if (bls_msg.has_finish_req()) {
        HandleFinish(*header, bls_msg);
        return;
    }

    if (waiting_bls_ != nullptr) {
        waiting_bls_->HandleMessage(header);
    }
}

bool BlsManager::IsSignValid(
        const elect::MembersPtr& members,
        const protobuf::BlsMessage& bls_msg,
        std::string* content_to_hash) {
    if (!security::IsValidSignature(bls_msg.sign_ch(), bls_msg.sign_res())) {
        BLS_ERROR("invalid sign: %s, %s!",
            common::Encode::HexEncode(bls_msg.sign_ch()),
            common::Encode::HexEncode(bls_msg.sign_res()));
        return false;
    }

    for (int32_t i = 0; i < bls_msg.finish_req().bitmap_size(); ++i) {
        *content_to_hash += std::to_string(bls_msg.finish_req().bitmap(i));
    }

    *content_to_hash += std::string("_") + std::to_string(bls_msg.finish_req().network_id());
    *content_to_hash = common::Hash::keccak256(*content_to_hash);
    auto& pubkey = (*members)[bls_msg.index()]->pubkey;
    std::string pk_str;
    pubkey.Serialize(pk_str);
//     std::cout << "finish message coming." << bls_msg.finish_req().network_id()
//         << ", id: " << common::Encode::HexEncode(security::Secp256k1::Instance()->ToAddressWithPublicKey(pk_str)) << std::endl;

    auto sign = security::Signature(bls_msg.sign_ch(), bls_msg.sign_res());
    if (!security::Schnorr::Instance()->Verify(*content_to_hash, sign, pubkey)) {
        return false;
    }

    return true;
}

void BlsManager::HandleFinish(
        const transport::protobuf::Header& header,
        const protobuf::BlsMessage& bls_msg) {
    if (bls_msg.finish_req().network_id() < network::kRootCongressNetworkId ||
            bls_msg.finish_req().network_id() >= network::kConsensusShardEndNetworkId) {
        return;
    }

    auto members = elect::ElectManager::Instance()->GetWaitingNetworkMembers(
        bls_msg.finish_req().network_id());
    if (members == nullptr || bls_msg.index() >= members->size()) {
        BLS_ERROR("not get waiting network members network id: %u, index: %d",
            bls_msg.finish_req().network_id(), bls_msg.index());
        return;
    }

    std::string msg_hash;
    if (!IsSignValid(members, bls_msg, &msg_hash)) {
        BLS_ERROR("IsSignValid failed network id: %u",
            bls_msg.finish_req().network_id());
        return;
    }

    std::vector<std::string> pkey_str = {
            bls_msg.finish_req().pubkey().x_c0(),
            bls_msg.finish_req().pubkey().x_c1(),
            bls_msg.finish_req().pubkey().y_c0(),
            bls_msg.finish_req().pubkey().y_c1()
    };
    auto t = common::GetSignerCount(members->size());
    BLSPublicKey pkey(std::make_shared<std::vector<std::string>>(pkey_str));
    std::vector<std::string> common_pkey_str = {
            bls_msg.finish_req().common_pubkey().x_c0(),
            bls_msg.finish_req().common_pubkey().x_c1(),
            bls_msg.finish_req().common_pubkey().y_c0(),
            bls_msg.finish_req().common_pubkey().y_c1()
    };
    BLSPublicKey common_pkey(std::make_shared<std::vector<std::string>>(common_pkey_str));
    std::string common_pk_str;
    for (uint32_t i = 0; i < common_pkey_str.size(); ++i) {
        common_pk_str += common_pkey_str[i];
    }

    std::string cpk_hash = common::Hash::Hash256(common_pk_str);
    std::lock_guard<std::mutex> guard(finish_networks_map_mutex_);
    BlsFinishItemPtr finish_item = nullptr;
    auto iter = finish_networks_map_.find(bls_msg.finish_req().network_id());
    if (iter == finish_networks_map_.end()) {
        finish_item = std::make_shared<BlsFinishItem>();
        finish_networks_map_[bls_msg.finish_req().network_id()] = finish_item;
    } else {
        finish_item = iter->second;
    }

    auto common_pk_iter = finish_item->common_pk_map.find(msg_hash);
    if (common_pk_iter == finish_item->common_pk_map.end()) {
        finish_item->common_pk_map[cpk_hash] = *common_pkey.getPublicKey();
    }

    finish_item->all_public_keys[bls_msg.index()] = *pkey.getPublicKey();
    auto cpk_iter = finish_item->max_public_pk_map.find(cpk_hash);
    if (cpk_iter == finish_item->max_public_pk_map.end()) {
        finish_item->max_public_pk_map[cpk_hash] = 1;
    } else {
        ++cpk_iter->second;
    }

    auto max_iter = finish_item->max_bls_members.find(msg_hash);
    if (max_iter != finish_item->max_bls_members.end()) {
        ++max_iter->second->count;
        if (max_iter->second->count > finish_item->max_finish_count) {
            finish_item->max_finish_count = max_iter->second->count;
            finish_item->max_finish_hash = msg_hash;
//             std::cout << "finsh called: " << bls_msg.finish_req().network_id() << ", "
//                 << common::Encode::HexEncode(msg_hash)
//                 << ", count: " << finish_item->max_finish_count
//                 << std::endl;
        }

        return;
    }

    std::vector<uint64_t> bitmap_data;
    for (int32_t i = 0; i < bls_msg.finish_req().bitmap_size(); ++i) {
        bitmap_data.push_back(bls_msg.finish_req().bitmap(i));
    }

    common::Bitmap bitmap(bitmap_data);
    auto item = std::make_shared<MaxBlsMemberItem>(1, bitmap);
    finish_item->max_bls_members[msg_hash] = item;
    if (finish_item->max_finish_count == 0) {
        finish_item->max_finish_count = 1;
        finish_item->max_finish_hash = msg_hash;
    }
}

void BlsManager::AddBlsConsensusInfo(elect::protobuf::ElectBlock& ec_block) {
    std::lock_guard<std::mutex> guard(finish_networks_map_mutex_);
    auto iter = finish_networks_map_.find(ec_block.shard_network_id());
    if (iter == finish_networks_map_.end()) {
        BLS_ERROR("find finish_networks_map_ failed![%u]", ec_block.shard_network_id());
        return;
    }

    auto members = elect::ElectManager::Instance()->GetWaitingNetworkMembers(
        ec_block.shard_network_id());
    if (members == nullptr) {
        BLS_ERROR("get waiting members failed![%u]", ec_block.shard_network_id());
        return;
    }

    // At least so many nodes are required to successfully exchange keys
    auto exchange_member_count = (uint32_t)((float)members->size() * kBlsMaxExchangeMembersRatio);
    if (exchange_member_count < members->size()) {
        ++exchange_member_count;
    }

    auto t = common::GetSignerCount(members->size());
    BlsFinishItemPtr finish_item = iter->second;
    if (finish_item->max_finish_count < exchange_member_count) {
        BLS_ERROR("finish_item->max_finish_count < t[%u][%u]",
            finish_item->max_finish_count, exchange_member_count);
        return;
    }

    auto item_iter = finish_item->max_bls_members.find(finish_item->max_finish_hash);
    if (item_iter == finish_item->max_bls_members.end()) {
        BLS_ERROR("finish_item->max_bls_members failed");
        return;
    }

    uint32_t max_mem_size = item_iter->second->bitmap.data().size() * 64;
    if (max_mem_size < members->size()) {
        BLS_ERROR("max_mem_size < members->size()[%u][%u]", max_mem_size, members->size());
        return;
    }

    auto pre_ec_members = ec_block.mutable_prev_members();
    uint32_t all_valid_count = 0;
    for (size_t i = 0; i < members->size(); ++i) {
        auto mem_bls_pk = pre_ec_members->add_bls_pubkey();
        if (!item_iter->second->bitmap.Valid(i)) {
            mem_bls_pk->set_x_c0("");
            mem_bls_pk->set_x_c1("");
            mem_bls_pk->set_y_c0("");
            mem_bls_pk->set_y_c1("");
            continue;
        }

        if (finish_item->all_public_keys[i] == libff::alt_bn128_G2::zero()) {
            mem_bls_pk->set_x_c0("");
            mem_bls_pk->set_x_c1("");
            mem_bls_pk->set_y_c0("");
            mem_bls_pk->set_y_c1("");
            continue;
        }

        finish_item->all_public_keys[i].to_affine_coordinates();
        mem_bls_pk->set_x_c0(
            crypto::ThresholdUtils::fieldElementToString(finish_item->all_public_keys[i].X.c0));
        mem_bls_pk->set_x_c1(
            crypto::ThresholdUtils::fieldElementToString(finish_item->all_public_keys[i].X.c1));
        mem_bls_pk->set_y_c0(
            crypto::ThresholdUtils::fieldElementToString(finish_item->all_public_keys[i].Y.c0));
        mem_bls_pk->set_y_c1(
            crypto::ThresholdUtils::fieldElementToString(finish_item->all_public_keys[i].Y.c1));
        BLS_DEBUG("AddBlsConsensusInfo success node index: %d,"
            "x_c0: %s, x_c1: %s, y_c0: %s, y_c1: %s.",
            i,
            mem_bls_pk->x_c0().c_str(), mem_bls_pk->x_c1().c_str(),
            mem_bls_pk->y_c0().c_str(), mem_bls_pk->y_c1().c_str());
        ++all_valid_count;
    }

    if (all_valid_count < t) {
        ec_block.clear_prev_members();
        BLS_ERROR("all_valid_count < t[%u][%u]", all_valid_count, t);
        return;
    }

    uint32_t max_cpk_count = 0;
    std::string max_cpk_hash;
    for (auto max_cpk_count_iter = finish_item->max_public_pk_map.begin();
            max_cpk_count_iter != finish_item->max_public_pk_map.end(); ++max_cpk_count_iter) {
        if (max_cpk_count_iter->second > max_cpk_count) {
            max_cpk_count = max_cpk_count_iter->second;
            max_cpk_hash = max_cpk_count_iter->first;
        }
    }

    auto common_pk_iter = finish_item->common_pk_map.find(max_cpk_hash);
    if (common_pk_iter == finish_item->common_pk_map.end()) {
        BLS_ERROR("finish_item->common_pk_map failed!");
        return;
    }

    common_pk_iter->second.to_affine_coordinates();
    auto common_pk = pre_ec_members->mutable_common_pubkey();
    common_pk->set_x_c0(
        crypto::ThresholdUtils::fieldElementToString(common_pk_iter->second.X.c0));
    common_pk->set_x_c1(
        crypto::ThresholdUtils::fieldElementToString(common_pk_iter->second.X.c1));
    common_pk->set_y_c0(
        crypto::ThresholdUtils::fieldElementToString(common_pk_iter->second.Y.c0));
    common_pk->set_y_c1(
        crypto::ThresholdUtils::fieldElementToString(common_pk_iter->second.Y.c1));
    pre_ec_members->set_prev_elect_height(
        elect::ElectManager::Instance()->waiting_elect_height(ec_block.shard_network_id()));
    BLS_DEBUG("AddBlsConsensusInfo success max_finish_count_: %d,"
        "member count: %d, x_c0: %s, x_c1: %s, y_c0: %s, y_c1: %s.",
        all_valid_count, members->size(),
        common_pk->x_c0().c_str(), common_pk->x_c1().c_str(),
        common_pk->y_c0().c_str(), common_pk->y_c1().c_str());
//     std::cout << "AddBlsConsensusInfo success max_finish_count_: " << all_valid_count
//         << ", member count: " << members->size()
//         << ", " << common_pk->x_c0()
//         << ", " << common_pk->x_c1()
//         << ", " << common_pk->y_c0()
//         << ", " << common_pk->y_c1()
//         << std::endl;
}

BlsManager::BlsManager() {
    initLibSnark();
    network::Route::Instance()->RegisterMessage(
        common::kBlsMessage,
        std::bind(&BlsManager::HandleMessage, this, std::placeholders::_1));
}

BlsManager::~BlsManager() {}

};  // namespace bls

};  // namespace tenon
