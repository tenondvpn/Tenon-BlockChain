#include "stdafx.h"
#include "transport/http/http_transport.h"

#include <queue>

#include "common/global_info.h"
#include "common/encode.h"
#include "common/hash.h"
#include "common/user_property_key_define.h"
#include "common/time_utils.h"
#include "common/string_utils.h"
#include "common/country_code.h"
#include "contract/contract_manager.h"
#include "statistics/statistics.h"
#include "security/secp256k1.h"
#include "db/db.h"
#include "security/schnorr.h"
#include "security/sha256.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "network/route.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "block/account_manager.h"

namespace tenon {

namespace transport {

HttpTransport::HttpTransport() {}
HttpTransport::~HttpTransport() {}

int HttpTransport::Init() {
    if (!http_svr_.is_valid()) {
        return -1;
    }
    return kTransportSuccess;
}

int HttpTransport::Start(bool hold) {
    if (hold) {
        Listen();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&HttpTransport::Listen, this));
        run_thread_->detach();
    }
    return kTransportSuccess;
}

static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;

static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
    broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kBftBroadcastStopTimes);
    broad_param->set_hop_limit(kBftHopLimit);
    broad_param->set_hop_to_layer(kBftHopToLayer);
    broad_param->set_neighbor_count(kBftNeighborCount);
}

// static std::string CreateWxAliPayRequest(
//         std::string& gid,
//         std::string& to,
//         uint64_t amount,
//         transport::protobuf::Header& msg) {
//     if (gid.empty()) {
//         gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
//     }
// 
//     auto uni_dht = std::dynamic_pointer_cast<network::Universal>(
//             network::UniversalManager::Instance()->GetUniversal(
//             network::kUniversalNetworkId));
//     if (!uni_dht) {
//         return "";
//     }
// 
//     msg.set_src_dht_key(uni_dht->local_node()->dht_key());
//     uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
//     dht::DhtKeyManager dht_key(des_net_id, 0);
//     msg.set_des_dht_key(dht_key.StrKey());
//     msg.set_priority(transport::kTransportPriorityHighest);
//     msg.set_id(common::GlobalInfo::Instance()->MessageId());
//     msg.set_type(common::kBftMessage);
//     msg.set_client(false);
//     msg.set_hop_count(0);
//     auto broad_param = msg.mutable_broadcast();
//     SetDefaultBroadcastParam(broad_param);
//     bft::protobuf::BftMessage bft_msg;
//     bft_msg.set_gid(gid);
//     bft_msg.set_rand(0);
//     bft_msg.set_bft_step(bft::kBftInit);
//     bft_msg.set_leader(false);
//     bft_msg.set_net_id(des_net_id);
//     bft_msg.set_node_id(common::GlobalInfo::Instance()->id());
//     bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
//     bft::protobuf::TxBft tx_bft;
//     auto new_tx = tx_bft.mutable_new_tx();
//     new_tx->set_gid(gid);
//     new_tx->set_from(common::GlobalInfo::Instance()->id());
//     new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
//     new_tx->set_to(to);
//     new_tx->set_amount(amount);
//     auto tx_data = tx_bft.SerializeAsString();
//     bft_msg.set_data(tx_data);
// 
//     auto hash128 = common::Hash::Hash128(tx_data);
//     security::Signature sign;
//     if (!security::Schnorr::Instance()->Sign(
//             hash128,
//             *(security::Schnorr::Instance()->prikey()),
//             *(security::Schnorr::Instance()->pubkey()),
//             sign)) {
//         TRANSPORT_ERROR("leader pre commit signature failed!");
//         return "";
//     }
//     std::string sign_challenge_str;
//     std::string sign_response_str;
//     sign.Serialize(sign_challenge_str, sign_response_str);
//     bft_msg.set_sign_challenge(sign_challenge_str);
//     bft_msg.set_sign_response(sign_response_str);
//     msg.set_data(bft_msg.SerializeAsString());
//     return gid;
// }

static void UseLocalCreateTxRequest(
        const nlohmann::json& data,
        std::string& account_address,
        transport::protobuf::Header& msg) {
    auto prikey = *security::Schnorr::Instance()->prikey();
    auto pubkey = *security::Schnorr::Instance()->pubkey();
    std::string str_pubkey = security::Schnorr::Instance()->str_pubkey();
    auto gid = common::Encode::HexDecode(data["gid"].get<std::string>());
    auto to = common::Encode::HexDecode(data["to"].get<std::string>());
    auto uni_dht = std::dynamic_pointer_cast<network::Universal>(
            network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId));
    if (!uni_dht) {
        return;
    }

    msg.set_src_dht_key(uni_dht->local_node()->dht_key());
    account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(str_pubkey);
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft_msg.set_node_id(account_address);
    bft_msg.set_pubkey(str_pubkey);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_amount(data["amount"].get<uint64_t>());
    new_tx->set_gid(gid);
    new_tx->set_from(account_address);
    new_tx->set_from_pubkey(str_pubkey);
    new_tx->set_to(to);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);

    TRANSPORT_ERROR("use local account new tx, from: %s, to: %s, amount: %lu",
        common::Encode::HexEncode(account_address).c_str(),
        data["to"].get<std::string>().c_str(),
        data["amount"].get<uint64_t>());
    auto hash128 = common::Hash::Hash128(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            prikey,
            pubkey,
            sign)) {
        TRANSPORT_ERROR("leader pre commit signature failed!");
        return;
    }
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

void HttpTransport::HandleTx(const httplib::Request &req, httplib::Response &res) {
    std::map<std::string, std::string> params;
    std::string account_address;
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        nlohmann::json data = json_obj["data"];
        transport::protobuf::Header msg;
        UseLocalCreateTxRequest(data, account_address, msg);
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
    } catch (std::exception& e) {
        res.status = 400;
        TRANSPORT_ERROR("HandleTx error.");
        return;
    }
    res.set_content(common::Encode::HexEncode(account_address), "text/plain");
    res.set_header("Access-Control-Allow-Origin", "*");
    return;
}

static void CreateTxRequest(
        const nlohmann::json& data,
        std::string& account_address,
        transport::protobuf::Header& msg) {
    auto prikey = security::PrivateKey(common::Encode::HexDecode(
        data["prikey"].get<std::string>()));
    auto pubkey = security::PublicKey(prikey);
    std::string str_pubkey;
    pubkey.Serialize(str_pubkey);
    auto gid = common::Encode::HexDecode(data["gid"].get<std::string>());
    auto to = common::Encode::HexDecode(data["to"].get<std::string>());
    msg.set_src_dht_key(common::Encode::HexDecode(
            data["src_dht_key"].get<std::string>()));
    account_address = security::Secp256k1::Instance()->ToAddressWithPublicKey(str_pubkey);
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    if (msg.src_dht_key().empty()) {
        dht::DhtKeyManager src_dht_key(des_net_id, 0);
        msg.set_src_dht_key(src_dht_key.StrKey());
    }

    TRANSPORT_ERROR("local transaction called: gid: %s, prikey: %s, to: %s, amount: %llu.",
        data["gid"].get<std::string>().c_str(),
        data["prikey"].get<std::string>().c_str(),
        data["to"].get<std::string>().c_str(),
        data["amount"].get<uint64_t>());

    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft_msg.set_node_id(account_address);
    bft_msg.set_pubkey(str_pubkey);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_amount(data["amount"].get<uint64_t>());
    new_tx->set_gid(gid);
    new_tx->set_from(account_address);
    new_tx->set_from_pubkey(str_pubkey);
    new_tx->set_to(to);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);
    auto hash128 = common::Hash::Hash128(tx_data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            prikey,
            pubkey,
            sign)) {
        TRANSPORT_ERROR("leader pre commit signature failed!");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
}

void HttpTransport::HandleTransaction(const httplib::Request &req, httplib::Response &res) {
    std::map<std::string, std::string> params;
    std::string account_address;
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        nlohmann::json data = json_obj["data"];
        transport::protobuf::Header msg;
        CreateTxRequest(data, account_address, msg);
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
    } catch (std::exception& e) {
        res.status = 400;
        TRANSPORT_ERROR("HandleTransaction error.");
        return;
    }

    res.set_content(common::Encode::HexEncode(account_address), "text/plain");
    res.set_header("Access-Control-Allow-Origin", "*");
    return;
}

void HttpTransport::HandleLocalTransaction(const httplib::Request &req, httplib::Response &res) {
    auto iter = req.headers.find("REMOTE_ADDR");
    if (iter == req.headers.end()) {
        res.status = 400;
        res.set_content("", "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
        TRANSPORT_ERROR("can't find remote addr from req.headers.");
        return;
    }

    TRANSPORT_ERROR("HandleLocalTransaction remote addr: %s", iter->second.c_str());
    if (iter->second != "127.0.0.1") {
        res.status = 400;
        res.set_content("", "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
        TRANSPORT_ERROR("remote addr [%s] local [%s] invalid.",
                iter->second.c_str(),
                "127.0.0.1");
        return;
    }

    std::map<std::string, std::string> params;
    std::string account_address;
    try {
        nlohmann::json data = nlohmann::json::parse(req.body);
        transport::protobuf::Header msg;
        CreateTxRequest(data, account_address, msg);
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
    } catch (std::exception& e) {
        res.status = 400;
        TRANSPORT_ERROR("HandleTransaction error.%s", e.what());
        return;
    }

    res.set_content(common::Encode::HexEncode(account_address), "text/plain");
    res.set_header("Access-Control-Allow-Origin", "*");
}

void HttpTransport::HandleAccountBalance(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        auto acc_addr = common::Encode::HexDecode(json_obj["acc_addr"].get<std::string>());
        auto acc_info_ptr = block::AccountManager::Instance()->GetAcountInfo(acc_addr);
        if (acc_info_ptr == nullptr) {
            res.set_content(std::to_string(-1), "text/plain");
            res.set_header("Access-Control-Allow-Origin", "*");
        } else {
            uint64_t db_balance = 0;
            if (acc_info_ptr->GetBalance(&db_balance) != block::kBlockSuccess) {
                BFT_ERROR("tx invalid. account address not exists");
            }

            res.set_content(std::to_string(db_balance), "text/plain");
            res.set_header("Access-Control-Allow-Origin", "*");
        }
    } catch (...) {
        res.status = 400;
        TRANSPORT_ERROR("account_balance by this node error.");
        std::cout << "account_balance by this node error." << std::endl;
    }
}

void HttpTransport::HandleGetTransaction(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        std::string block_hash;
        if (json_obj.find("tx_gid") != json_obj.end()) {
            auto src_tx_gid = common::Encode::HexDecode(json_obj["tx_gid"].get<std::string>());
            auto tx_gid = common::GetTxDbKey(false, src_tx_gid);
            auto st = db::Db::Instance()->Get(tx_gid, &block_hash);
            if (!st.ok()) {
                res.status = 201;
                res.set_content(common::Encode::HexEncode(src_tx_gid), "text/plain");
                res.set_header("Access-Control-Allow-Origin", "*");
                TRANSPORT_ERROR("account_balance by this node error. Get tx_gid");
                return;
            }
        }

        if (json_obj.find("block_hash") != json_obj.end()) {
            block_hash = common::Encode::HexDecode(json_obj["block_hash"].get<std::string>());
        }

        std::string block_data;
        auto st = db::Db::Instance()->Get(block_hash, &block_data);
        if (!st.ok()) {
            res.status = 201;
            res.set_content(common::Encode::HexEncode(block_hash), "text/plain");
            res.set_header("Access-Control-Allow-Origin", "*");
            TRANSPORT_ERROR("account_balance by this node error. Get block_hash");
            return;
        }

        bft::protobuf::Block block;
        if (!block.ParseFromString(block_data)) {
            res.status = 201;
            res.set_content(common::Encode::HexEncode(block_hash), "text/plain");
            res.set_header("Access-Control-Allow-Origin", "*");
            TRANSPORT_ERROR("account_balance by this node error. ParseFromString");
            return;
        }

        nlohmann::json res_json;
        res_json["block_height"] = block.height();
        res_json["block_hash"] = common::Encode::HexEncode(block.hash());
        res_json["prev_hash"] = common::Encode::HexEncode(block.prehash());
        res_json["transaction_size"] = block.tx_list_size();
        auto tx_list_res = res_json["tx_list"];
        auto tx_list = block.tx_list();
        for (int32_t i = 0; i < tx_list.size(); ++i) {
            res_json["tx_list"][i]["tx_gid"] = common::Encode::HexEncode(tx_list[i].gid());
            res_json["tx_list"][i]["from"] = common::Encode::HexEncode(tx_list[i].from());
            res_json["tx_list"][i]["to"] = common::Encode::HexEncode(tx_list[i].to());
            res_json["tx_list"][i]["version"] = tx_list[i].version();
            res_json["tx_list"][i]["amount"] = tx_list[i].amount();
        }

        res.status = 200;
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (...) {
        res.set_content("", "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
        TRANSPORT_ERROR("account_balance by this node error.");
        std::cout << "account_balance by this node error." << std::endl;
    }
}

typedef std::shared_ptr<bft::protobuf::Block> BlockPtr;
struct BlockOperator {
    bool operator() (const BlockPtr& lhs, const BlockPtr& rhs) {
        return lhs->timestamp() > rhs->timestamp();
    }
};

typedef std::priority_queue<BlockPtr, std::vector<BlockPtr>, BlockOperator> PriQueue;
bool PushPriQueue(PriQueue& pri_queue, BlockPtr& item) {
    pri_queue.push(item);
    if (pri_queue.size() > 50) {
        auto tmp_item = pri_queue.top();
        pri_queue.pop();
        if (tmp_item->hash() == item->hash()) {
            return false;
        }
    }
    return true;
}

void HttpTransport::HandleListTransactions(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        std::string acc_addr;
        auto iter = json_obj.find("acc_addr");
        if (iter != json_obj.end()) {
            acc_addr = common::Encode::HexDecode(json_obj["acc_addr"].get<std::string>());
            if (!acc_addr.empty()) {
                // just get 100 this user block
                auto pool_idx = common::GetPoolIndex(acc_addr);
                std::string key = block::GetLastBlockHash(
                        common::GlobalInfo::Instance()->network_id(),
                        pool_idx);
                std::string block_hash;
                auto st = db::Db::Instance()->Get(key, &block_hash);
                if (!st.ok()) {
                    return;
                }

                nlohmann::json res_json;
                uint32_t block_idx = 0;
                uint32_t count = 0;
                while (count++ < 100) {
                    if (block_hash.empty()) {
                        break;
                    }

                    std::string block_str;
                    st = db::Db::Instance()->Get(block_hash, &block_str);
                    if (!st.ok()) {
                        continue;
                    }

                    auto block_ptr = std::make_shared<bft::protobuf::Block>();
                    if (!block_ptr->ParseFromString(block_str)) {
                        continue;
                    }

                    auto& tx_list = block_ptr->tx_list();
                    for (int32_t i = 0; i < tx_list.size(); ++i) {
                        if (tx_list[i].from() != acc_addr && tx_list[i].to() != acc_addr) {
                            continue;
                        }

                        res_json["data"][block_idx]["height"] = block_ptr->height();
                        res_json["data"][block_idx]["timestamp"] = block_ptr->timestamp();
                        res_json["data"][block_idx]["network_id"] = common::GlobalInfo::Instance()->network_id();
                        res_json["data"][block_idx]["add_to"] = tx_list[i].to_add();
                        res_json["data"][block_idx]["from"] = common::Encode::HexEncode(tx_list[i].from());
                        res_json["data"][block_idx]["to"] = common::Encode::HexEncode(tx_list[i].to());
                        if (tx_list[i].to_add()) {
                            res_json["data"][block_idx]["pool_idx"] = common::GetPoolIndex(tx_list[i].to());
                        }
                        else {
                            res_json["data"][block_idx]["pool_idx"] = common::GetPoolIndex(tx_list[i].from());
                        }
                        res_json["data"][block_idx]["gas_price"] = tx_list[i].gas_price();
                        res_json["data"][block_idx]["amount"] = tx_list[i].amount();
                        res_json["data"][block_idx]["version"] = tx_list[i].version();
                        res_json["data"][block_idx]["gid"] = common::Encode::HexEncode(tx_list[i].gid());
                        res_json["data"][block_idx]["balance"] = tx_list[i].balance();
                        res_json["data"][block_idx]["type"] = tx_list[i].type();
                        ++block_idx;
                        if (block_idx >= 100) {
                            break;
                        }
                    }

                    if (block_idx >= 100) {
                        break;
                    }
                    block_hash = block_ptr->prehash();
                }
                res_json["type"] = 0;
                res.set_content(res_json.dump(), "text/plain");
                res.set_header("Access-Control-Allow-Origin", "*");
                return;
            }
        }

        PriQueue pri_queue;
        for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
            std::string key = block::GetLastBlockHash(
                common::GlobalInfo::Instance()->network_id(),
                i);
            std::string block_hash;
            auto st = db::Db::Instance()->Get(key, &block_hash);
            if (!st.ok()) {
                continue;
            }

            uint32_t count = 0;
            while (count++ < 100) {
                if (block_hash.empty()) {
                    break;
                }

                std::string block_str;
                st = db::Db::Instance()->Get(block_hash, &block_str);
                if (!st.ok()) {
                    continue;
                }

                auto block_ptr = std::make_shared<bft::protobuf::Block>();
                if (!block_ptr->ParseFromString(block_str)) {
                    continue;
                }

                if (!PushPriQueue(pri_queue, block_ptr)) {
                    break;
                }
                block_hash = block_ptr->prehash();
            }
        }

        nlohmann::json res_json;
        uint32_t block_idx = 0;
        while (!pri_queue.empty()) {
            auto item = pri_queue.top();
            pri_queue.pop();
            auto& tx_list = item->tx_list();
            for (int32_t i = 0; i < tx_list.size(); ++i) {
                res_json["data"][block_idx]["height"] = item->height();
                res_json["data"][block_idx]["timestamp"] = item->timestamp();
                res_json["data"][block_idx]["network_id"] = common::GlobalInfo::Instance()->network_id();
                res_json["data"][block_idx]["add_to"] = tx_list[i].to_add();
                res_json["data"][block_idx]["from"] = common::Encode::HexEncode(tx_list[i].from());
                res_json["data"][block_idx]["to"] = common::Encode::HexEncode(tx_list[i].to());
                if (tx_list[i].to_add()) {
                    res_json["data"][block_idx]["pool_idx"] = common::GetPoolIndex(tx_list[i].to());
                } else {
                    res_json["data"][block_idx]["pool_idx"] = common::GetPoolIndex(tx_list[i].from());
                }
                res_json["data"][block_idx]["gas_price"] = tx_list[i].gas_price();
                res_json["data"][block_idx]["amount"] = tx_list[i].amount();
                res_json["data"][block_idx]["version"] = tx_list[i].version();
                res_json["data"][block_idx]["gid"] = common::Encode::HexEncode(tx_list[i].gid());
                res_json["data"][block_idx]["balance"] = tx_list[i].balance();
                res_json["data"][block_idx]["type"] = tx_list[i].type();
                ++block_idx;
            }
        }
        res_json["type"] = 1;
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (...) {
        res.status = 400;
        TRANSPORT_ERROR("account_balance by this node error.");
        std::cout << "account_balance by this node error." << std::endl;
    }
}

void HttpTransport::HandleTxInfo(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        auto acc_addr = common::Encode::HexDecode(json_obj["acc_addr"].get<std::string>());
        auto acc_ptr = block::AccountManager::Instance()->GetAcountInfo(acc_addr);
        nlohmann::json res_json;
        res_json["tx_count"] = statis::Statistics::Instance()->all_tx_count();
        res_json["tx_amount"] = statis::Statistics::Instance()->all_tx_amount();
        res_json["tps"] = statis::Statistics::Instance()->tps();
        if (acc_ptr != nullptr) {
            uint64_t db_balance = 0;
            if (acc_ptr->GetBalance(&db_balance) != block::kBlockSuccess) {
                BFT_ERROR("tx invalid. account address not exists");
            }

            uint64_t create_account_height = 0;
            if (acc_ptr->GetCreateAccountHeight(&create_account_height) != block::kBlockSuccess) {
                return;
            }

            uint64_t height = 0;
            if (acc_ptr->GetMaxHeight(&height) != block::kBlockSuccess) {
                return;
            }
            res_json["balance"] = db_balance;
            res_json["in"] = 0;
            res_json["out"] = 0;
            res_json["in_lego"] = 0;
            res_json["out_lego"] = 0;
            res_json["create_account_height"] = create_account_height;
            res_json["height"] = height;
        }
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (...) {
        res.status = 400;
        TRANSPORT_ERROR("account_balance by this node error.");
        std::cout << "account_balance by this node error." << std::endl;
    }
}

void HttpTransport::HandleStatistics(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json res_json;
        res_json["all_tx_count"] = statis::Statistics::Instance()->all_tx_count();
        res_json["all_tx_amount"] = statis::Statistics::Instance()->all_tx_amount();
        res_json["tx_count"] = statis::Statistics::Instance()->tx_count();
        res_json["tx_amount"] = statis::Statistics::Instance()->tx_amount();
        res_json["addr_count"] = statis::Statistics::Instance()->get_addr_count();
        res_json["tps"] = statis::Statistics::Instance()->tps();
        res_json["tps_q"] = statis::Statistics::Instance()->tps_queue();
        res_json["tx_count_q"] = statis::Statistics::Instance()->tx_count_q();
        res_json["tx_amount_q"] = statis::Statistics::Instance()->tx_amount_q();
        res_json["addr_q"] = statis::Statistics::Instance()->new_user_count(true, 128);
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (...) {
        res.status = 400;
        TRANSPORT_ERROR("HandleStatistics by this node error.");
        std::cout << "HandleStatistics by this node error." << std::endl;
    }
}

void HttpTransport::HandleBestAddr(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json res_json;
        statis::Statistics::Instance()->GetBestAddr(res_json);
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (...) {
        res.status = 400;
        TRANSPORT_ERROR("HandleBestAddr by this node error.");
        std::cout << "HandleBestAddr by this node error." << std::endl;
    }
}

void HttpTransport::HandleIosPay(const httplib::Request &req, httplib::Response &res) {
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        auto acc_addr = common::Encode::HexDecode(json_obj["acc_addr"].get<std::string>());
        nlohmann::json res_json;
        res_json["tx_count"] = statis::Statistics::Instance()->all_tx_count();
        res_json["tx_amount"] = statis::Statistics::Instance()->all_tx_amount();
        res_json["tps"] = statis::Statistics::Instance()->tps();
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (...) {
        res.status = 400;
        TRANSPORT_ERROR("HandleBestAddr by this node error.");
        std::cout << "HandleBestAddr by this node error." << std::endl;
    }
}

std::string HttpTransport::GetCountryLoad(int32_t pre_days) try {
    std::map<int32_t, int32_t> res_map;
    for (int i = 0; i < pre_days; ++i) {
        std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays() - i);
        if (pre_days == 100) {
            now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays() - 1);
        }
        std::string attr_key = common::kVpnClientLoginAttr + now_day_timestamp;
        std::string attr_val;
        assert(false);
//         contract::ContractManager::Instance()->GetAttrWithKey(
//                 contract::kVpnClientLoginManager,
//                 attr_key,
//                 attr_val);
        common::Split<> splits(attr_val.c_str(), ',', attr_val.size());
        for (uint32_t i = 0; i < splits.Count(); ++i) {
            common::Split<> tmp_split(splits[i], ':', splits.SubLen(i));
            if (tmp_split.Count() != 2) {
                continue;
            }

            int32_t key = 0;
            common::StringUtil::ToInt32(tmp_split[0], &key);
            int32_t val = 0;
            common::StringUtil::ToInt32(tmp_split[1], &val);
            auto iter = res_map.find(key);
            if (iter == res_map.end()) {
                res_map[key] = val;
                continue;
            }

            iter->second += val;
        }

        if (pre_days == 100) {
            break;
        }
    }

    struct CountryItem {
        int32_t country;
        int32_t count;
        bool operator < (const CountryItem& x) const {
            return this->count < x.count;
        }
        CountryItem(int32_t cty, int32_t cnt) : country(cty), count(cnt) {}
    };

    std::priority_queue<CountryItem> country_queue;
    for (auto iter = res_map.begin(); iter != res_map.end(); ++iter) {
        country_queue.push(CountryItem(iter->first, iter->second));
    }

    std::string res_str;
    int count = 0;
    int32_t other = 0;
    while (!country_queue.empty()) {
        CountryItem item = country_queue.top();
        country_queue.pop();
        if (count < 16) {
            res_str += common::global_code_to_country_english_map[item.country] + ":" + std::to_string(item.count) + ",";
        } else {
            other += item.count;
        }
    }

    res_str += "other:" + std::to_string(other) + ",";
    return res_str;
} catch (...) {
    return "error";
}

void HttpTransport::HandleGetCountryLoad(
        const httplib::Request &req,
        httplib::Response &res) {
    try {
        nlohmann::json json_obj = nlohmann::json::parse(req.body);
        auto type = json_obj["type"].get<int32_t>();
        std::string val_str = GetCountryLoad(type);
        if (val_str.empty()) {
            return;
        }

        nlohmann::json res_json;
        res_json["val"] = val_str;
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (std::exception& e) {
        res.status = 400;
        TRANSPORT_ERROR("HandleGetCountryLoad by this node error.");
        std::cout << "HandleGetCountryLoad by this node error." << e.what() << std::endl;
    }
}

void HttpTransport::HandleGetDayAlive(const httplib::Request &req, httplib::Response &res) {
    try {
        std::string val_str;
//         contract::ContractManager::Instance()->GetAttrWithKey(
//                 contract::kContractVpnBandwidthProveAddr,
//                 common::kActiveUser,
//                 val_str);
        auto actives = statis::Statistics::Instance()->active_user_count(1, 30);
        for (auto iter = actives.rbegin(); iter != actives.rend(); ++iter) {
            val_str += std::to_string(*iter) + ",";
        }

        nlohmann::json res_json;
        res_json["val"] = val_str;
        res.set_content(res_json.dump(), "text/plain");
        res.set_header("Access-Control-Allow-Origin", "*");
    } catch (std::exception& e) {
        res.status = 400;
        TRANSPORT_ERROR("HandleGetCountryLoad by this node error.");
        std::cout << "HandleGetCountryLoad by this node error." << e.what() << std::endl;
    }
}

void HttpTransport::Listen() {
    http_svr_.Get("/http_message", [=](const httplib::Request& req, httplib::Response &res) {
        std::cout << "http get request size: " << req.body.size() << std::endl;
        res.set_content("Hello World!\n", "text/plain");
    });
    http_svr_.Post("/tx", [&](const httplib::Request &req, httplib::Response &res) {
        HandleTx(req, res);
    });
    http_svr_.Post("/transaction", [&](const httplib::Request &req, httplib::Response &res) {
        HandleTransaction(req, res);
    });
    http_svr_.Post("/local_transaction", [&](const httplib::Request &req, httplib::Response &res) {
        TRANSPORT_ERROR("local_transaction coming.");
        HandleLocalTransaction(req, res);
    });
    http_svr_.Post("/account_balance", [&](const httplib::Request &req, httplib::Response &res) {
        HandleAccountBalance(req, res);
    });
    http_svr_.Post("/get_transaction", [&](const httplib::Request &req, httplib::Response &res) {
        HandleGetTransaction(req, res);
    });
    http_svr_.Post("/list_transaction", [&](const httplib::Request &req, httplib::Response &res) {
        HandleListTransactions(req, res);
    });
    http_svr_.Post("/tx_info", [&](const httplib::Request &req, httplib::Response &res) {
        HandleTxInfo(req, res);
    });
    http_svr_.Post("/statistics", [&](const httplib::Request &req, httplib::Response &res) {
        HandleStatistics(req, res);
    });
    http_svr_.Post("/best_addr", [&](const httplib::Request &req, httplib::Response &res) {
        HandleBestAddr(req, res);
    });
    http_svr_.Post("/ios_pay", [&](const httplib::Request &req, httplib::Response &res) {
        HandleIosPay(req, res);
    });
    http_svr_.Post("/get_country_load", [&](const httplib::Request &req, httplib::Response &res) {
        HandleGetCountryLoad(req, res);
    });
    http_svr_.Post("/get_day_actives", [&](const httplib::Request &req, httplib::Response &res) {
        HandleGetDayAlive(req, res);
    });
    http_svr_.set_error_handler([](const httplib::Request&, httplib::Response &res) {
        const char *fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
    });

    if (!http_svr_.listen(
        common::GlobalInfo::Instance()->config_local_ip().c_str(),
        common::GlobalInfo::Instance()->http_port())) {
        assert(false);
        exit(1);
    }
}

void HttpTransport::Stop() {
    http_svr_.stop();
}

int HttpTransport::Send(
    const std::string& ip,
    uint16_t port,
    uint32_t ttl,
    transport::protobuf::Header& message) {
    assert(false);
    return kTransportSuccess;
}

int HttpTransport::SendToLocal(transport::protobuf::Header& message) {
    assert(false);
    return kTransportSuccess;
}

int HttpTransport::GetSocket() {
    assert(false);
    return kTransportSuccess;
}

}  // namespace transport

}  // namespace tenon
