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
#include "security/security.h"
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
        const std::string& contract_addr,
        const std::map<std::string, std::string>& attrs,
        transport::protobuf::Header& msg) {
    auto from = security::Secp256k1::Instance()->ToAddressWithPublicKey(from_pk);
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(from);
    if (account_info == nullptr) {
        return kAccountNotExists;
    }

    int64_t balance = 0;
    if (account_info->GetBalance(&balance) != block::kBlockSuccess ||
            (balance + gas_limit * gas_price) < amount) {
        return kBalanceInvalid;
    }

    uint32_t des_net_id = 0;
    if (account_info->SetConsensuseNetid(&network_id) != block::kBlockSuccess) {
        return kShardIdInvalid;
    }

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
    bft_msg.set_pubkey(security::Security::Instance()->str_pubkey());
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from(from);
    new_tx->set_from_pubkey(from_pk);
    new_tx->set_type(type);
    new_tx->set_to(to);
    new_tx->set_amount(amount);
    new_tx->set_gas_limit(gas_limit);
    new_tx->set_gas_price(gas_price);
    for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
        auto server_attr = new_tx->add_attr();
        server_attr->set_key(iter->first);
        server_attr->set_value(iter->second);
    }

    auto sechash = bft::GetTxMessageHash(*new_tx);
    auto sign = security::Signature(sign_r, sign_s);
    if (!security::Security::Instance()->Verify(sechash, sign, from_pk)) {
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
    if (gid == nullptr || from == nullptr || to == nullptr ||
            amount == nullptr || gas_limit == nullptr ||
            gas_price == nullptr || sigR == nullptr ||
            sigS == nullptr || type == nullptr) {
        std::string res = common::StringUtil::Format(
            "param invalid gid: %d, from: %d, to: %d,"
            "amount: %d, gas_limit: %d, gas_price: %d, sigR: %d, sigS: %d, type: %d \n",
            (gid != nullptr), (from != nullptr), (to != nullptr),
            (amount != nullptr), (gas_limit != nullptr),
            (gas_price != nullptr), (sigR != nullptr),
            (sigS != nullptr), (type != nullptr));
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
    if (!common::StringUtil::ToUint64(std::string(type), &type_val)) {
        std::string res = std::string("type not integer: ") + type;
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

    const std::map<std::string, std::string> attrs;
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
        "",
        attrs,
        msg);
    if (status != kHttpSuccess) {
        std::string res = std::string("transaction invalid: ") + kStatusMap[status];
        evbuffer_add(req->buffer_out, res.c_str(), res.size());
        evhtp_send_reply(req, EVHTP_RES_OK);
        return;
    }

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
