#include <gtest/gtest.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

static const int PORT = 9995;
static char g_szWriteMsg[256] = { 0 };
static char g_szReadMsg[256] = { 0 };
static int g_iCnt = 0;
static void conn_writecb(struct bufferevent *, void *);
static void conn_readcb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);
#include <iostream>
#define private public
#include "tcp/tcp_server.h"
#include "tcp/tcp_client.h"

#define BUFFSIZE 1024
volatile bool stop = false;

static void
conn_writecb(struct bufferevent *bev, void *user_data)
{
    //printf("touch conn_writecb\n");

//    if ( strlen(g_szWriteMsg) > 0 )
//    {
//        bufferevent_write(bev, g_szWriteMsg, strlen(g_szWriteMsg));
//        memset(g_szWriteMsg, 0x00, sizeof(g_szWriteMsg));
//    }
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
    //printf("touch conn_readcb\n");
    memset(g_szReadMsg, 0x00, sizeof(g_szReadMsg));
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t sz = evbuffer_get_length(input);
    if (sz > 0)
    {
        bufferevent_read(bev, g_szReadMsg, sz);
        printf("ser:>>%s\n", g_szReadMsg);
        memset(g_szWriteMsg, 0, sizeof(g_szWriteMsg));
        snprintf(g_szWriteMsg, sizeof(g_szWriteMsg) - 1, "hi server,this count is %d", g_iCnt);
        g_iCnt++;
        //printf("cli:>>");
        //gets(g_szWriteMsg);
        //scanf("%s", g_szWriteMsg);
        bufferevent_write(bev, g_szWriteMsg, strlen(g_szWriteMsg));
    }
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    if (events & BEV_EVENT_EOF) {
        printf("Connection closed.\n");
    }
    else if (events & BEV_EVENT_ERROR) {
        printf("Got an error on the connection: %s\n",
            strerror(errno));/*XXX win32*/
    }
    else if (events & BEV_EVENT_CONNECTED)
    {
        //Go here when the connection is successful, and the connection is really established only after the client triggers the read event for the first time.
        printf("connect success\n");
        const char* msg = "hi server,hao are you";
        bufferevent_write(bev, msg, strlen(msg));
        return;
    }
    bufferevent_free(bev);
}
namespace tenon {

namespace tcp {

namespace test {

static const uint32_t kThreadCount = 10;
uint32_t thread_arr1[kThreadCount] = { 0 };

class TestTcpServer : public testing::Test {
public:
    static void SetUpTestCase() {
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestTcpServer, TestServer) {
    TcpServer tcp_server;
    char res[1024] = { 0 };
    auto callback = [&tcp_server, res](TcpConnection* con) ->int32_t {
        uint32_t* header = (uint32_t*)res;
        header[0] = htonl(con->index);
        return tcp_server.Send(con, res, con->index);
    };

    ASSERT_EQ(tcp_server.Init(4, 3000, "127.0.0.1", 9090, callback), 0);
    tcp_server.Start();
    std::vector<std::thread> thread_vec;
    TcpClient::InitClientLoop();
    TcpClient clients[kThreadCount];
    TcpClientCallback callbacks[kThreadCount];
    TcpClientEventCallback ev_callbacks[kThreadCount];
    char send_buff[BUFFSIZE];
    std::string test_str = "hello world.";
    uint32_t* header = (uint32_t*)send_buff;
    header[0] = htonl(test_str.size() + 4);
    memcpy(send_buff + kTcpHeaderLen, test_str.c_str(), test_str.size());
    send_buff[test_str.size() + 4] = '\0';
    int32_t send_size = test_str.size() + 4;
    for (int32_t i = 0; i < kThreadCount; ++i) {
        callbacks[i] = [&clients, send_buff, send_size, i](const char* data, int32_t len) ->int32_t {
            clients[i].Send(send_buff, send_size);
            ++thread_arr1[i];
            return 0;
        };

        ev_callbacks[i] = [i](int32_t event)->int32_t {
            std::cout << "thread i: " << i << ", get event: " << event << std::endl;
        };
    }

    for (int32_t i = 0; i < kThreadCount; ++i) {
        ASSERT_EQ(clients[i].Connect("127.0.0.1", 9090, ev_callbacks[i], callbacks[i]), 0);
    }

    for (int32_t i = 0; i < kThreadCount; ++i) {
        clients[i].Send(send_buff, send_size);
    }

    sleep(1);
    for (int32_t i = 0; i < kThreadCount; ++i) {
        ASSERT_EQ(clients[i].Reconnect(), 0);
        clients[i].Send(send_buff, send_size);
    }

    sleep(2);
    tcp_server.Stop();
    TcpClient::StopClientLoop();
    for (int32_t i = 0; i < kThreadCount; ++i) {
        std::cout << thread_arr1[i] << ", ";
        EXPECT_TRUE(thread_arr1[0] > 100);
    }

    std::cout << std::endl;
}

}  // namespace test

}  // namespace tcp

}  // namespace tenon
