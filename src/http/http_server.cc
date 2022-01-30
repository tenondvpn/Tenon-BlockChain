#include "http/http_server.h"

#include <signal.h>
#include <functional>
#include <map>

#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "block/account_manager.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "security/security.h"
#include "security/public_key.h"
#include "security/signature.h"
#include "transport/multi_thread.h"

namespace tenon {

namespace http {

static HttpServer* http_server = nullptr;

static int CreateTransactionWithAttr(
        const std::string& gid,
        const std::string& from_pk,
        const std::string& to,
        const std::string& sign_r,
        const std::string& sign_s,
        uint64_t amount,
        uint64_t gas_limit,
        uint64_t gas_price,
        uint32_t type,
        int32_t des_net_id,
        const std::string& contract_addr,
        evhtp_kvs_t* evhtp_kvs,
        transport::protobuf::Header& msg) {
    auto from = security::Secp256k1::Instance()->ToAddressWithPublicKey(from_pk);
    std::cout << common::Encode::HexEncode(from_pk) << ", " << common::Encode::HexEncode(from) << ", " << common::Encode::HexEncode(to) << std::endl;
    if (from.empty()) {
        return kAccountNotExists;
    }

    if (from == to) {
        return kFromEqualToInvalid;
    }
//     auto account_info = block::AccountManager::Instance()->GetAcountInfo(from);
//     if (account_info == nullptr) {
//         return kAccountNotExists;
//     }
// 
//     uint64_t balance = 0;
//     if (account_info->GetBalance(&balance) != block::kBlockSuccess ||
//             (balance + gas_limit * gas_price) < amount) {
//         return kBalanceInvalid;
//     }
// 
//     uint32_t des_net_id = 0;
//     if (account_info->GetConsensuseNetId(&des_net_id) != block::kBlockSuccess) {
//         return kShardIdInvalid;
//     }

    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_src_dht_key(dht_key.StrKey());
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    transport::SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_pubkey(from_pk);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from(from);
    new_tx->set_type(type);
    new_tx->set_to(to);
    new_tx->set_amount(amount);
    new_tx->set_gas_limit(gas_limit);
    new_tx->set_gas_price(gas_price);

    const char* attr_size_param = evhtp_kv_find(evhtp_kvs, "attrs_size");
    if (attr_size_param != nullptr) {
        int32_t attr_size = 0;
        if (!common::StringUtil::ToInt32(std::string(attr_size_param), &attr_size)) {
            std::string res = std::string("attr_size not integer: ") + attr_size_param;
            evbuffer_add(req->buffer_out, res.c_str(), res.size());
            evhtp_send_reply(req, EVHTP_RES_OK);
            return kHttpError;
        }

        for (int32_t i = 0; i < attr_size; ++i) {
            std::string key = std::string("key") + std::to_string(i);
            std::string val = std::string("val") + std::to_string(i);
            const char* key_p = evhtp_kv_find(evhtp_kvs, key.c_str());
            const char* val_p = evhtp_kv_find(evhtp_kvs, val.c_str());
            if (key_p == nullptr || val_p == nullptr) {
                std::string res = std::string("attr invalid: ") + key + " or " + val;
                evbuffer_add(req->buffer_out, res.c_str(), res.size());
                evhtp_send_reply(req, EVHTP_RES_OK);
                return kHttpError;
            }

            auto server_attr = new_tx->add_attr();
            server_attr->set_key(key_p);
            server_attr->set_value(val_p);
        }
    }

    auto sechash = bft::GetTxMessageHash(*new_tx);
    auto sign = security::Signature(sign_r, sign_s);
    auto pk = security::PublicKey(from_pk);
    if (!security::Security::Instance()->Verify(sechash, sign, pk)) {
        return kSignatureInvalid;
    }

    auto data = tx_bft.SerializeAsString();
    bft_msg.set_data(data);
    bft_msg.set_sign_challenge(sign_r);
    bft_msg.set_sign_response(sign_s);
    std::string s_data = bft_msg.SerializeAsString();
    msg.set_data(s_data);
    return kHttpSuccess;
}

static void TransactionCallback(evhtp_request_t* req, void* data) {
//     auto b_time_1 = common::GetTimestampUs();
    auto header1 = evhtp_header_new("Access-Control-Allow-Origin", "*", 0, 0);
    auto header2 = evhtp_header_new("Access-Control-Allow-Methods", "POST", 0, 0);
    auto header3 = evhtp_header_new(
        "Access-Control-Allow-Headers",
        "x-requested-with,content-type", 0, 0);
    evhtp_headers_add_header(req->headers_out, header1);
    evhtp_headers_add_header(req->headers_out, header2);
    evhtp_headers_add_header(req->headers_out, header3);
    const char* gid = evhtp_kv_find(req->uri->query, "gid");
    const char* frompk = evhtp_kv_find(req->uri->query, "frompk");
    const char* to = evhtp_kv_find(req->uri->query, "to");
    const char* amount = evhtp_kv_find(req->uri->query, "amount");
    const char* gas_limit = evhtp_kv_find(req->uri->query, "gas_limit");
    const char* gas_price = evhtp_kv_find(req->uri->query, "gas_price");
    const char* sigR = evhtp_kv_find(req->uri->query, "sigR");
    const char* sigS = evhtp_kv_find(req->uri->query, "sigS");
    const char* type = evhtp_kv_find(req->uri->query, "type");
    const char* shard_id = evhtp_kv_find(req->uri->query, "shard_id");
    if (gid == nullptr || frompk == nullptr || to == nullptr ||
            amount == nullptr || gas_limit == nullptr ||
            gas_price == nullptr || sigR == nullptr ||
            sigS == nullptr || type == nullptr || shard_id == nullptr) {
        std::string res = common::StringUtil::Format(
            "param invalid gid: %d, frompk: %d, to: %d,"
            "amount: %d, gas_limit: %d, gas_price: %d, sigR: %d, sigS: %d,"
            "type: %d, shard_id: %d \n",
            (gid != nullptr), (frompk != nullptr), (to != nullptr),
            (amount != nullptr), (gas_limit != nullptr),
            (gas_price != nullptr), (sigR != nullptr),
            (sigS != nullptr), (type != nullptr), (shard_id != nullptr));
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    uint64_t amount_val = 0;
    if (!common::StringUtil::ToUint64(std::string(amount), &amount_val)) {
        std::string res = std::string("amount not integer: ") + amount;
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    uint64_t gas_limit_val = 0;
    if (!common::StringUtil::ToUint64(std::string(gas_limit), &gas_limit_val)) {
        std::string res = std::string("gas_limit not integer: ") + gas_limit;
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    uint64_t gas_price_val = 0;
    if (!common::StringUtil::ToUint64(std::string(gas_price), &gas_price_val)) {
        std::string res = std::string("gas_price not integer: ") + gas_price;
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    int32_t type_val = 0;
    if (!common::StringUtil::ToInt32(std::string(type), &type_val)) {
        std::string res = std::string("type not integer: ") + type;
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    int32_t shard_id_val = 0;
    if (!common::StringUtil::ToInt32(std::string(shard_id), &shard_id_val)) {
        std::string res = std::string("type not integer: ") + shard_id;
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    transport::protobuf::Header msg;
    int status = CreateTransactionWithAttr(
        common::Encode::HexDecode(gid),
        common::Encode::HexDecode(frompk),
        common::Encode::HexDecode(to),
        common::Encode::HexDecode(sigR),
        common::Encode::HexDecode(sigS),
        amount_val,
        gas_limit_val,
        gas_price_val,
        type_val,
        shard_id_val,
        "",
        req->uri->query,
        msg);
    if (status != kHttpSuccess) {
        std::string res = std::string("transaction invalid: ") + GetStatus(status);
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    network::Route::Instance()->Send(msg);
    std::string res = std::string("ok");
    evbuffer_add(req->buffer_out, res.c_str(), res.size());
    evhtp_send_reply(req, EVHTP_RES_OK);
}

HttpServer::HttpServer() {
    http_server = this;
}

HttpServer::~HttpServer() {}

HttpServer* HttpServer::Instance() {
    static HttpServer ins;
    return &ins;
}

int32_t HttpServer::Init(
        const char* ip,
        uint16_t port,
        int32_t thread_count) {
    evbase_ = event_base_new();
    if (evbase_ == nullptr) {
        return kHttpError;
    }

    htp_ = evhtp_new(evbase_, NULL);
    if (htp_ == nullptr) {
        return kHttpError;
    }

    evhtp_set_cb(
        htp_,
        "/do_transaction",
        TransactionCallback,
        NULL);
    evhtp_use_threads_wexit(htp_, NULL, NULL, thread_count, NULL);
    evhtp_bind_socket(htp_, ip, port, 1024);
    TENON_INFO("start http server: %s: %d", ip, port);
    return kHttpSuccess;
}

int32_t HttpServer::Start() {
    if (htp_ == nullptr) {
        return kHttpError;
    }

    http_thread_ = new std::thread(std::bind(&HttpServer::RunHttpServer, this));
    http_thread_->detach();
    return kHttpSuccess;
}

void HttpServer::RunHttpServer() {
    event_base_loop(evbase_, 0);
}

int32_t HttpServer::Stop() {
    if (evbase_ != nullptr) {
        event_base_loopexit(evbase_, NULL);
    }

    if (http_thread_ != nullptr) {
        delete http_thread_;
        http_thread_ = nullptr;
    }

    if (ev_sigint_ != nullptr) {
        evhtp_safe_free(ev_sigint_, event_free);
    }

    if (htp_ != nullptr) {
        evhtp_unbind_socket(htp_);
        evhtp_safe_free(htp_, evhtp_free);
    }

    if (evbase_ != nullptr) {
        evhtp_safe_free(evbase_, event_base_free);
    }

    return kHttpSuccess;
}

};  // namespace tenon

};  // namespace tenon
