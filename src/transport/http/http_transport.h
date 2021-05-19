#pragma once

#include <mutex>
#include <unordered_map>
#include <set>

#include "transport/transport.h"
#include "common/tick.h"
#include "httplib.h"

namespace tenon {

namespace transport {

enum TransactionType {
    kBuyWithWxAliPay = 0,
    kSharedStaking = 1,
};

class HttpTransport : public Transport {
public:
    HttpTransport();
    virtual ~HttpTransport();
    virtual int Init();
    virtual int Start(bool hold);
    virtual void Stop();
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            transport::protobuf::Header& message);
    virtual int SendToLocal(transport::protobuf::Header& message);
    virtual int GetSocket();
    virtual void FreeConnection(const std::string& ip, uint16_t port) {}

private:
    void Listen();
    void HandleTx(const httplib::Request &req, httplib::Response &res);
    void HandleTransaction(const httplib::Request &req, httplib::Response &res);
    void HandleLocalTransaction(const httplib::Request &req, httplib::Response &res);
	void HandleAccountBalance(const httplib::Request &req, httplib::Response &res);
	void HandleGetTransaction(const httplib::Request &req, httplib::Response &res);
	void HandleListTransactions(const httplib::Request &req, httplib::Response &res);
    void HandleTxInfo(const httplib::Request &req, httplib::Response &res);
    void HandleStatistics(const httplib::Request &req, httplib::Response &res);
    void HandleBestAddr(const httplib::Request &req, httplib::Response &res);
    void HandleIosPay(const httplib::Request &req, httplib::Response &res);
    void HandleGetCountryLoad(const httplib::Request &req, httplib::Response &res);
    std::string GetCountryLoad(int32_t type);
    void HandleGetDayAlive(const httplib::Request &req, httplib::Response &res);

    httplib::Server http_svr_;
    std::shared_ptr<std::thread> run_thread_{ nullptr };
    std::unordered_map<std::string, uint32_t> shared_staking_map_;
    std::mutex shared_staking_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(HttpTransport);
};

}  // namespace transport

}  // namespace tenon
