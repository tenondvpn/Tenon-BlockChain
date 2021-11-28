#include "stdafx.h"
#include "init/command.h"

#include <iostream>
#include <string>
#include <stdio.h>
#include <termios.h> 
#include <unistd.h>

#include <iostream>
#include <memory>
#include <thread>

#include "common/split.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/country_code.h"
#include "common/time_utils.h"
#include "common/shell_utils.h"
#include "db/db.h"
#include "block/block_utils.h"
#include "db/db.h"
#include "dht/base_dht.h"
#include "dht/dht_key.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "network/route.h"
#include "network/network_utils.h"
#include "bft/bft_manager.h"
#include "init/init_utils.h"
#include "contract/contract_utils.h"
#include "client/vpn_client.h"
#include "client/trans_client.h"
#include "client/proto/client_proto.h"
#include "block/account_manager.h"
#include "ip/ip_with_country.h"
#include "statistics/statistics.h"
// #include "services/vpn_server/server.h"
// #include "services/vpn_server/vpn_server.h"
#undef _WIN32
#ifndef _WIN32
#include "security/private_key.h"
#include "security/public_key.h"
#include "tvm/execution.h"
#include "tvm/tenon_host.h"
#include "init/genesis_block_init.h"
#endif

namespace tenon {

namespace init {

Command::Command() {}

Command::~Command() {
    destroy_ = true;
}

#ifdef _WIN32
bool Command::Init(bool first_node, bool show_cmd, bool period_tick) {
    return true;
}
void Command::Run() {}
void Command::Help() {}

#else

bool Command::Init(bool first_node, bool show_cmd, bool period_tick) {
    first_node_ = first_node;
    show_cmd_ = show_cmd;
    AddBaseCommands();
    if (period_tick) {
        tx_tick_.CutOff(kTransportTestPeriod, std::bind(&Command::TxPeriod, this));
    }

//     LoadAllNodesAndCheckPort();
    return true;
}

int clear_icanon(void) {
    struct termios settings;
    int result;
    result = tcgetattr(STDIN_FILENO, &settings);
    if (result < 0) {
        perror("error in tcgetattr");
        return 0;
    }

    settings.c_lflag &= ~ICANON;
    result = tcsetattr(STDIN_FILENO, TCSANOW, &settings);
    if (result < 0) {
        perror("error in tcsetattr");
        return 0;
    }
    return 1;
}

void Command::Run() {
    Help();
    clear_icanon();
    while (!common::global_stop) {
        if (!show_cmd_) {
            std::this_thread::sleep_for(std::chrono::microseconds(200000ll));
            continue;
        }

        std::cout << std::endl << std::endl << "cmd > ";
//         char data[1024 * 100 + 1] = { 0 };
//         std::cin.getline(data, sizeof(data) - 1);
        std::string cmdline;
        std::getline(std::cin, cmdline);
//         std::string data;
//         std::cin >> data;
//         std::cout << data.length() << std::endl;
        ProcessCommand(cmdline);
    }
}

void Command::ProcessCommand(const std::string& cmdline) {
    if (cmdline.empty()) {
        return;
    }

    std::string cmd;
    std::vector<std::string> args;
    try {
        common::Split<> line_split(cmdline.c_str(), ' ', cmdline.size());
        cmd = "";
        for (uint32_t i = 0; i < line_split.Count(); ++i) {
            if (strlen(line_split[i]) == 0) {
                continue;
            }

            if (cmd == "") {
                cmd = line_split[i];
            } else {
                args.push_back(line_split[i]);
            }
        }
    } catch (const std::exception& e) {
        INIT_WARN("Error processing command: %s", e.what());
    }

    std::unique_lock<std::mutex> lock(cmd_map_mutex_);
    auto it = cmd_map_.find(cmd);
    if (it == cmd_map_.end()) {
        std::cout << "Invalid command : " << cmd << std::endl;
    } else {
        try {
            (it->second)(args);
        } catch (std::exception& e) {
            std::cout << "catch error: " << e.what() << std::endl;
        }
    }
}

void Command::AddCommand(const std::string& cmd_name, CommandFunction cmd_func) {
    assert(cmd_func);
    std::unique_lock<std::mutex> lock(cmd_map_mutex_);
    auto it = cmd_map_.find(cmd_name);
    if (it != cmd_map_.end()) {
        INIT_WARN("command(%s) exist and ignore new one", cmd_name.c_str());
        return;
    }
    cmd_map_[cmd_name] = cmd_func;
}

void Command::AddBaseCommands() {
    AddCommand("help", [this](const std::vector<std::string>& args) {
        Help();
    });
    AddCommand("prt", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }
        uint32_t network_id = 0;
        common::StringUtil::ToUint32(args[0], &network_id);
        PrintDht(network_id);
    });
    AddCommand("get", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }
        
        std::string val;
        db::Db::Instance()->Get(args[0], &val);
        std::cout << args[0] << ":" << val << std::endl;
    });
    AddCommand("gete", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        std::string val;
        db::Db::Instance()->Get(common::Encode::HexDecode(args[0]), &val);
        std::cout << args[0] << ":" << common::Encode::HexEncode(val) << std::endl;
    });
    AddCommand("mem", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }
        uint32_t network_id = 0;
        common::StringUtil::ToUint32(args[0], &network_id);
        PrintMembers(network_id);
    });
    AddCommand("p2p", [this](const std::vector<std::string>& args) {
        if (args.size() > 0) {
            PrivateKeyToPublicKey(args[0]);
        }
    });
    AddCommand("b", [this](const std::vector<std::string>& args) {
        std::cout << common::GlobalInfo::Instance()->consensus_shard_net_id() << ", balance: " << client::VpnClient::Instance()->GetBalance() << std::endl;
    });
    AddCommand("cc", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        std::string bytes_code = common::Encode::HexDecode(args[0]);
        uint64_t amount = 0;
        if (args.size() > 1) {
            common::StringUtil::ToUint64(args[1], &amount);
        }

        uint64_t gas_limit = 10000000;
        if (args.size() > 2) {
            common::StringUtil::ToUint64(args[2], &gas_limit);
        }

        std::string contract_address;
        client::VpnClient::Instance()->CreateContract(bytes_code, amount, gas_limit, &contract_address);
        std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    });
    AddCommand("cca", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        CallContract(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });

    AddCommand("ballot_create", [this](const std::vector<std::string>& args) {
        std::string contract_addr = CreateContractBallot();
    });
    AddCommand("ballot_create_and_set_voters", [this](const std::vector<std::string>& args) {
        std::string contract_addr = CreateContractBallot();
        ChairmanSetVoters(contract_addr);
    });
    AddCommand("ballot_chairman_set_voter", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }
        //     std::vector<std::string> voters = {
//         "544064949151817a1185e931ea43a71493f9f33c",
//         "15518b7643b094a6b1faba3a91fc16c20a9041da",
//         "7c4fd7e97e3cdd18dbe56e1256fbd60d4129af66",
//         "7027d87b3b251eac11933b5c2e4bd2ff1f7dd666",
//         "a2234d38e7073639156ee1cfc323e8d6cdadc604",
//         "2935aeb958731e29b8297d7250903b86c22b40be",
//         "14f87c1026d307937b6160ca69b24e891467749b",
//         "4dca4186ec80fe5bbce7531186fc8966d8dd58a9",
//         "a45c90f01155cd8615d2db4267b6ee0e8e3d6528",
//         "cc686eefa301ec1a781a77a915a742cc5f562613",
//     };

        ChairmanSetVoter(common::Encode::HexDecode(args[0]), args[1]);
    });
    AddCommand("ballot_set_del", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        VoterSetDelegate(common::Encode::HexDecode(args[0]), args[1]);
    });
    AddCommand("ballot_vote", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        Vote(common::Encode::HexDecode(args[0]));
    });
    AddCommand("ballot_win", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        GetWinner(common::Encode::HexDecode(args[0]));
    });
    AddCommand("receive_pay_create", [this](const std::vector<std::string>& args) {
        CreateReceivePay();
    });
    AddCommand("receive_pay", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        ReceivePay(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });
    AddCommand("auction_create", [this](const std::vector<std::string>& args) {
        CreateSimpleAuction();
    });
    AddCommand("auction_bid", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        uint64_t amount = 0;
        if (!common::StringUtil::ToUint64(args[1], &amount)) {
            return;
        }

        SimpleAuctionBid(common::Encode::HexDecode(args[0]), amount);
    });
    AddCommand("auction_withdraw", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        SimpleAuctionWithDraw(common::Encode::HexDecode(args[0]));
    });
    AddCommand("auction_end", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        SimpleAuctionEnd(common::Encode::HexDecode(args[0]));
    });

    // blind auction
    AddCommand("blind_auction_create", [this](const std::vector<std::string>& args) {
        CreateBlindAuction();
    });
    AddCommand("blind_auction_bid", [this](const std::vector<std::string>& args) {
        if (args.size() < 3) {
            return;
        }

        uint64_t amount = 0;
        if (!common::StringUtil::ToUint64(args[2], &amount)) {
            return;
        }

        BlindAuctionBit(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]), amount);
    });
    AddCommand("blind_auction_reveal", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        BlindAuctionReveal(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });
    AddCommand("blind_auction_withdraw", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        BlindAuctionWithdraw(common::Encode::HexDecode(args[0]));
    });
    AddCommand("blind_auction_end", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        BlindAuctionEnd(common::Encode::HexDecode(args[0]));
    });

    // purchase
    AddCommand("purchase_create", [this](const std::vector<std::string>& args) {
        CreatePurchase();
    });
    AddCommand("purchase_abort", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        PurchaseAbort(common::Encode::HexDecode(args[0]));
    });
    AddCommand("purchase_confirm_purchase", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        PurchaseConfirmPurchase(common::Encode::HexDecode(args[0]));
    });
    AddCommand("purchase_confirm_receive", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        PurchaseConfirmReceived(common::Encode::HexDecode(args[0]));
    });
    AddCommand("purchase_refundseller", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        PurchaseRefundSeller(common::Encode::HexDecode(args[0]));
    });

    // payment channel
    AddCommand("payment_create", [this](const std::vector<std::string>& args) {
        CreatePaymentChannel();
    });
    AddCommand("payment_close", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        ChannelClose(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });
    AddCommand("payment_extend", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        ChannelExtend(common::Encode::HexDecode(args[0]));
    });
    AddCommand("payment_timeout", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        ChannelClaimTimeout(common::Encode::HexDecode(args[0]));
    });

    // token inner
    AddCommand("token_create", [this](const std::vector<std::string>& args) {
        CreateToken();
    });
    AddCommand("token_create_addr", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        TokenCreateAddr(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });
    AddCommand("token_balance", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        TokenBalance(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });
    AddCommand("token_approve", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        TokenApprove(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });
    AddCommand("token_transfer", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        TokenTransfer(common::Encode::HexDecode(args[0]), common::Encode::HexDecode(args[1]));
    });

    // ex token
    AddCommand("ex_token_create_lib", [this](const std::vector<std::string>& args) {
        CreateExTokenLib();
    });
    AddCommand("ex_token_create", [this](const std::vector<std::string>& args) {
        CreateExToken();
    });

    // internal math add
    AddCommand("math_create", [this](const std::vector<std::string>& args) {
        CreateTestMath();
    });
    AddCommand("math_add", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        MathAdd(common::Encode::HexDecode(args[0]));
    });
    // external math add
    AddCommand("ex_math_create_lib", [this](const std::vector<std::string>& args) {
        CreateExternMathLib();
    });
    AddCommand("ex_math_create", [this](const std::vector<std::string>& args) {
        CreateExternMath();
    });
    AddCommand("ex_math_add", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        ExtenMathAdd(common::Encode::HexDecode(args[0]));
    });

    AddCommand("rc", [this](const std::vector<std::string>& args) {
        CheckAllNodePortValid();
    });
    AddCommand("vn", [this](const std::vector<std::string>& args) {
        std::string country = "US";
        bool is_vip = false;
        if (args.size() > 0) {
            country = args[0];
        }

        if (args.size() > 1) {
            is_vip = true;
        }

        GetVpnNodes(country, is_vip);
    });
    AddCommand("rn", [this](const std::vector<std::string>& args) {
        std::string country = "US";
        bool is_vip = false;
        if (args.size() > 0) {
            country = args[0];
        }

        if (args.size() > 1) {
            is_vip = true;
        }
        
        GetRouteNodes(country, is_vip);
    });
    AddCommand("vh", [this](const std::vector<std::string>& args) {
        if (args.size() > 0) {
            VpnHeartbeat(args[0]);
        }
    });
    AddCommand("pt", [this](const std::vector<std::string>& args) {
        if (args.size() > 0) {
            uint32_t pool_idx = 0;
            common::StringUtil::ToUint32(args[0], &pool_idx);
            PrintPoolHeightTree(pool_idx);
        }
    });
	AddCommand("ip", [this](const std::vector<std::string>& args) {
		if (args.size() > 0) {
            std::cout << ip::IpWithCountry::Instance()->GetCountryCode(args[0]) << std::endl;
		}
	});
    AddCommand("ltx", [this](const std::vector<std::string>& args) {
        std::cout << client::VpnClient::Instance()->Transactions(0, 10) << std::endl;
    });
	AddCommand("nv", [this](const std::vector<std::string>& args) {
		std::string download_url = (
			"ios;1.0.3;https://www.pgyer.com/1U2f,"
			"android;1.0.3;https://www.pgyer.com/62Dg,"
			"windows;1.0.3;https://github.com/actantion/tenon_vpn-win10/archive/1.0.3.zip,"
			"mac;1.0.3;");
		if (args.size() > 0) {
			download_url = args[0];
		}

		CreateNewVpnVersion(download_url);
	});
    AddCommand("vl", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        std::vector<std::string> route_vec;
        route_vec.push_back("test_route1");
        route_vec.push_back("test_route2");
        std::string account = "test_account";
        std::string gid;
        std::cout << client::VpnClient::Instance()->VpnLogin(
                common::Encode::HexDecode(args[0]),
                route_vec,
                gid) << std::endl;
        std::cout << "gid:" << gid << std::endl;
    });
    AddCommand("vs", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

//         auto acc_item = std::make_shared<BandwidthInfo>(
//                 10, 10, common::Encode::HexDecode(args[0]));
//         tenon::vpn::VpnServer::Instance()->bandwidth_queue().push(acc_item);

    });
    AddCommand("ab", [this](const std::vector<std::string>& args) {
        if (args.size() < 3) {
            return;
        }

        uint32_t count = 9;
        common::StringUtil::ToUint32(args[2], &count);
        for (uint32_t i = 0; i < count; ++i) {
            std::string to = common::Encode::HexDecode(args[0]);
            uint32_t amount = 0;
            common::StringUtil::ToUint32(args[1], &amount);
            SendClientUseBandwidth(to, amount);
            std::cout << i << ": " << count << std::endl;
            std::this_thread::sleep_for(std::chrono::microseconds(50000ull));
        }
    });
    AddCommand("fdb", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        std::string db_path = args[0];
        FixDb(db_path);
    });
    AddCommand("tvm", [this](const std::vector<std::string>& args) {
//         tvm::Execution exec;
        std::string code;
        if (args.size() >= 1) {
            code = common::Encode::HexDecode(args[0]);
        }

        std::string input;
        if (args.size() >= 2) {
            input = common::Encode::HexDecode(args[1]);
        }
        
        evmc_result evmc_res = {};
        evmc::result res{ evmc_res };
        tvm::TenonHost tenon_host;
        tvm::Execution::Instance()->execute(code, input, "", "", "", 0, 0, 0, false, tenon_host, &res);
    });
    AddCommand("ltr", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        std::string db_path = args[0];
        LevelDbToRocksDb(db_path);
    });
    AddCommand("st", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        int32_t type = atoi(args[0].c_str());
        if (type == 0) {
            std::cout << "addr_count: " << statis::Statistics::Instance()->get_addr_count() << std::endl;
        } else if (type == 1) {
            {
                auto res = statis::Statistics::Instance()->active_user_count(0, 128);
                std::cout << "active_user_count for month: " << std::endl;
                for (auto iter = res.begin(); iter != res.end(); ++iter) {
                    std::cout << *iter << ' ';
                }

                std::cout << std::endl;
            }

            {
                auto res = statis::Statistics::Instance()->active_user_count(1, 128);
                std::cout << "active_user_count for day: " << std::endl;
                for (auto iter = res.begin(); iter != res.end(); ++iter) {
                    std::cout << *iter << ' ';
                }

                std::cout << std::endl;
            }

            {
                auto res = statis::Statistics::Instance()->active_user_count(2, 128);
                std::cout << "active_user_count for hour: " << std::endl;
                for (auto iter = res.begin(); iter != res.end(); ++iter) {
                    std::cout << *iter << ' ';
                }

                std::cout << std::endl;
            }
        } else if (type == 2) {
            std::cout << "tx_count: " << statis::Statistics::Instance()->tx_count() << std::endl;
            std::cout << "all_tx_count: " << statis::Statistics::Instance()->all_tx_count() << std::endl;
        } else if (type == 3) {
            std::cout << "tx_amount: " << statis::Statistics::Instance()->tx_amount() << std::endl;
            std::cout << "all_tx_amount: " << statis::Statistics::Instance()->all_tx_amount() << std::endl;
        } else if (type == 4) {
            std::cout << "all tenon: " << statis::Statistics::Instance()->get_all_lego() << std::endl;
        } else if (type == 5) {
            std::cout << "tps: " << statis::Statistics::Instance()->tps() << std::endl;
        }
        else if (type == 6) {
            {
                auto res = statis::Statistics::Instance()->new_user_count(true, 128);
                std::cout << "new_user_count for day: " << std::endl;
                for (auto iter = res.begin(); iter != res.end(); ++iter) {
                    std::cout << *iter << ' ';
                }

                std::cout << std::endl;
            }

            {
                auto res = statis::Statistics::Instance()->new_user_count(false, 128);
                std::cout << "new_user_count for hour: " << std::endl;
                for (auto iter = res.begin(); iter != res.end(); ++iter) {
                    std::cout << *iter << ' ';
                }

                std::cout << std::endl;
            }
        } else if (type == 7) {
            auto res = statis::Statistics::Instance()->tps_queue();
            std::cout << "tps_queue : " << std::endl;
            for (auto iter = res.begin(); iter != res.end(); ++iter) {
                std::cout << *iter << ' ';
            }

            std::cout << std::endl;
        } else if (type == 8) {
            auto res = statis::Statistics::Instance()->tx_count_q();
            std::cout << "tx_count_q : " << std::endl;
            for (auto iter = res.begin(); iter != res.end(); ++iter) {
                std::cout << *iter << ' ';
            }

            std::cout << std::endl;
        } else if (type == 9) {
            auto res = statis::Statistics::Instance()->tx_amount_q();
            std::cout << "tx_amount_q : " << std::endl;
            for (auto iter = res.begin(); iter != res.end(); ++iter) {
                std::cout << *iter << ' ';
            }

            std::cout << std::endl;
        } else if (type == 10) {
            auto res = statis::Statistics::Instance()->active_user_count(1, 128);
            std::cout << "addr_q : " << std::endl;
            for (auto iter = res.begin(); iter != res.end(); ++iter) {
                std::cout << *iter << ' ';
            }

            std::cout << std::endl;
        } else if (type == 11) {
            auto res = statis::Statistics::Instance()->best_addrs();
            std::cout << "best_addrs : " << std::endl;
            for (auto iter = res.begin(); iter != res.end(); ++iter) {
                statis::AccountBalance* item = (statis::AccountBalance*)((*iter).c_str());
                std::cout << common::Encode::HexEncode(std::string(item->account_id, sizeof(item->account_id)))
                    << ":" << item->balance << std::endl;
            }

            std::cout << std::endl;
        }
    });
    AddCommand("pb", [this](const std::vector<std::string>& args) {
        if (args.size() < 1) {
            return;
        }

        std::string block_hash;
        if (args[0].size() > 32) {
            block_hash = common::Encode::HexDecode(args[0]);
        } else {
            std::string pool_hash;
            uint64_t pool_height = 0;
            uint64_t tm_height;
            uint64_t tm_with_block_height;
            uint32_t tmp_val = 0;
            common::StringUtil::ToUint32(args[0], &tmp_val);
            int res = block::AccountManager::Instance()->GetBlockInfo(
                tmp_val,
                &pool_height,
                &pool_hash,
                &tm_height,
                &tm_with_block_height);
            if (res != block::kBlockSuccess) {
                return;
            }

            block_hash = pool_hash;
        }

        int count = 0;
        while (!block_hash.empty() && count++ < 10) {
            std::cout << "prehash: " << common::Encode::HexEncode(block_hash) << std::endl;
            std::string block_str;
            auto st = db::Db::Instance()->Get(block_hash, &block_str);
            if (!st.ok()) {
                return;
            }

            bft::protobuf::Block block_item;
            if (!block_item.ParseFromString(block_str)) {
                break;
            }

            block_hash = block_item.prehash();
        }
    });
    AddCommand("tx", [this](const std::vector<std::string>& args) {
        std::string tx_gid;
        std::string to;
        if (args.size() > 0) {
            to = args[0];
        }

        uint64_t amount = 0;
        if (args.size() > 1) {
            common::StringUtil::ToUint64(args[1], &amount);
        }
        tenon::client::VpnClient::Instance()->Transaction(to, amount, tx_gid);
    });
    AddCommand("pv", [this](const std::vector<std::string>& args) {
        std::string to;
        if (args.size() > 0) {
            to = args[0];
        }

        uint64_t amount = 0;
        if (args.size() > 1) {
            common::StringUtil::ToUint64(args[1], &amount);
        }
        std::string gid;
        auto tx_gid = tenon::client::VpnClient::Instance()->PayForVPN(to, gid, amount);
        std::cout << "pay for vpn: " << tx_gid << std::endl;
    });
    AddCommand("tcping", [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            return;
        }

        std::string cmd = std::string("./tcping ") + args[0] + " " + args[1];
        bool reachable = false;
        uint16_t tmp_val = 0;
        common::StringUtil::ToUint16(args[1], &tmp_val);
        common::RemoteReachable(args[0], tmp_val, &reachable);
        std::cout << "remote reachable: " << reachable << std::endl;
    });
    AddCommand("bg", [this](const std::vector<std::string>& args) {
        if (args.size() <= 0) {
            return;
        }

        std::string hash = args[0];
        bool is_gid = false;
        if (args.size() > 1) {
            common::StringUtil::ToBool(args[1], &is_gid);
        }

        std::shared_ptr<bft::protobuf::Block> block_ptr = nullptr;
        if (is_gid) {
            block_ptr = tenon::client::VpnClient::Instance()->GetBlockWithGid(hash);
        } else {
            block_ptr = tenon::client::VpnClient::Instance()->GetBlockWithHash(hash);
        }

        for (int i = 0; i < 3; ++i) {
            if (is_gid) {
                block_ptr = tenon::client::VpnClient::Instance()->GetBlockWithGid(hash);
            } else {
                block_ptr = tenon::client::VpnClient::Instance()->GetBlockWithHash(hash);
            }
            std::this_thread::sleep_for(std::chrono::microseconds(1000000ull));
        }
        std::cout << "get block info success." << std::endl;
        std::cout << "block height: " << block_ptr->height() << std::endl;
        std::cout << "block hash: " << common::Encode::HexEncode(block_ptr->hash()) << std::endl;
        std::cout << "prev hash: " << common::Encode::HexEncode(block_ptr->prehash()) << std::endl;
        std::cout << "transaction size: " << block_ptr->tx_list_size() << std::endl;
        auto tx_list = block_ptr->tx_list();
        for (int32_t i = 0; i < tx_list.size(); ++i) {
            std::cout << "\ttransaction gid: " << common::Encode::HexEncode(tx_list[i].gid()) << std::endl;
            std::cout << "\tfrom: " << common::Encode::HexEncode(tx_list[i].from()) << std::endl;
            std::cout << "\tto: " << common::Encode::HexEncode(tx_list[i].to()) << std::endl;
            std::cout << "\tamount: " << tx_list[i].amount() << std::endl;
            std::cout << "\ttype: " << tx_list[i].type() << std::endl;
            std::cout << "\tattr size: " << tx_list[i].attr_size() << std::endl;
            for (int32_t j = 0; j < tx_list[i].attr_size(); ++j) {
                std::cout << "\t\t" << tx_list[i].attr(j).key() << ": " << tx_list[i].attr(j).value() << std::endl;
            }
            std::cout << std::endl;
        }
    });
}

void Command::CreateNewVpnVersion(const std::string& download_url) {
	transport::protobuf::Header msg;
	uint64_t rand_num = 0;
	auto uni_dht = network::UniversalManager::Instance()->GetUniversal(
		network::kUniversalNetworkId);
	if (uni_dht == nullptr) {
		return;
	}
	auto ver_gid = common::CreateGID(security::Schnorr::Instance()->str_pubkey());
	uint32_t type = common::kConsensusTransaction;
	client::ClientProto::CreateClientNewVersion(
			uni_dht->local_node(),
			ver_gid,
			download_url,
			msg);
	network::Route::Instance()->Send(msg);
	std::cout << "sent create new version: " << download_url << std::endl;
}

void Command::TxPeriod() {
    const static std::vector<std::string> kToVec = {
        "ed8ff8be40cea693ccccdec322734efad3887c214d9b5b5d27e7eeb23f9bad57",
        "d13e2e80bfabf218571aa7d1e9d78725ac81a44c5ce1cdd26e26682f5fb074ea",
        "7ff1c9d61979ff5e628a462a12cf6bb37b0385999e4d38dba49b2f3b290cb629",
        "33db092901adfc31113bb4c8de4d02f71725ecab3cc6f80cbf17198a44d27042",
        "8362c14239913b0bba5cfde3077e7213f1dd63483b96c3a4d69c96b7bc880dd0",
        "562e22f17854a247bcb31b7593e3e7870de3e6185180f079bb7b9b3ff7d332ba",
        "1cbf2103db1fdb0257a4fed5fb4088ec0ee5ec092a16113acfd0d39b7fda32ef",
        "9933386363509f9cc38850819da15805c905b23ca0fe1b72e00167c733b612ad",
        "5ebd74cbdbb526380ff42ded6ec1e285b41f0adee552d7517c5bfd84ee4f893b",
        "eddfa882929c48b6021dfe2f44f7af49c6402c121965057f67fad275aec9e340",
        "07d2d95eb210cd897d255767e0e278d23e21193fbd3ba02452d4c0bf711f6a38",
        "46e404414a45abbb8375a07465445958a0485f692f3118e2e444b17c8b516bd2",
        "ed64f20aa64f4543162b7806c6205ae5655a469280531e58accd793f581387f4",
        "a67f5318d4355861b9fa4d8d7ebc346ae2154691ca7aaf90111e4d87f0e3254a",
        "72012a413fe07cc3fd6367489ce047e577f646e8c45cdf649bd23cb21c8b707e"
    };
    std::string to = kToVec[std::rand() % kToVec.size()];
    uint32_t amount = std::rand() % 100 + 10;
    std::string tx_gid;
    tenon::client::VpnClient::Instance()->Transaction(to, amount, tx_gid);
    tx_tick_.CutOff(kTransportTestPeriod, std::bind(&Command::TxPeriod, this));
    std::cout << "tx gid:" << tx_gid << " success transaction from: "
        << common::Encode::HexEncode(common::GlobalInfo::Instance()->id())
        << " to: " << to << " , amount: " << amount << std::endl;
}

void Command::PrintPoolHeightTree(uint32_t pool_idx) {
    block::AccountManager::Instance()->PrintPoolHeightTree(pool_idx);
}

void Command::VpnHeartbeat(const std::string& dht_key) {
    client::VpnClient::Instance()->VpnHeartbeat(dht_key);
}

void Command::GetVpnNodes(const std::string& country, bool is_vip) {
    std::vector<tenon::client::VpnServerNodePtr> nodes;
    tenon::client::VpnClient::Instance()->GetVpnServerNodes(country, "", 2, false, is_vip, nodes);
    std::cout << "get vpn_nodes size: " << nodes.size() << std::endl;
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << "get vpn_info: " << nodes[i]->ip << ":" << nodes[i]->svr_port
            << ", " << nodes[i]->svr_port << ", "
            << nodes[i]->seckey << ", "
            << nodes[i]->pubkey << ", "
            << nodes[i]->dht_key << std::endl;
    }
}

void Command::GetRouteNodes(const std::string& country, bool is_vip) {
    std::vector<tenon::client::VpnServerNodePtr> nodes;
    tenon::client::VpnClient::Instance()->GetVpnServerNodes(country, "", 2, true, is_vip, nodes);
    std::cout << "get route_nodes size: " << nodes.size() << std::endl;
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << "get route_info: " << nodes[i]->ip << ":" << nodes[i]->route_port
            << ", " << nodes[i]->route_port
            <<", " << nodes[i]->min_route_port
            <<", " << nodes[i]->max_route_port
            <<", " << nodes[i]->seckey << ", "
            << nodes[i]->pubkey << ", "
            << nodes[i]->dht_key << std::endl;
    }
}

void Command::PrintMembers(uint32_t network_id) {
    auto mem_ptr = bft::BftManager::Instance()->GetNetworkMembers(network_id);
    if (mem_ptr != nullptr) {
        for (auto iter = mem_ptr->begin(); iter != mem_ptr->end(); ++iter) {
            std::cout << (*iter)->id << std::endl;
        }
    }
}

void Command::PrintDht(uint32_t network_id) {
    auto base_dht = network::DhtManager::Instance()->GetDht(network_id);
    if (!base_dht) {
        base_dht = network::UniversalManager::Instance()->GetUniversal(network_id);
    }

    if (!base_dht) {
        return;
    }
    dht::DhtPtr readonly_dht = base_dht->readonly_dht();
    auto node = base_dht->local_node();
    std::cout << "dht nnum: " << readonly_dht->size() + 1 << std::endl;
    std::cout << "local: " << common::Encode::HexEncode(node->id()) << ":" << node->id_hash
        << ", " << common::Encode::HexSubstr(node->dht_key()) << ":" << node->dht_key_hash
        << ", " << node->public_ip() << ":" << node->public_port << std::endl;
    for (auto iter = readonly_dht->begin(); iter != readonly_dht->end(); ++iter) {
        auto node = *iter;
        assert(node != nullptr);
        auto country = common::global_code_to_country_map[
                dht::DhtKeyManager::DhtKeyGetCountry(node->dht_key())];
        std::cout << common::Encode::HexSubstr(node->id())
            << ", " << node->dht_key_hash
            << ", " << common::Encode::HexSubstr(node->dht_key()) << ", " << country
            << ", " << common::Encode::HexEncode(node->pubkey_str())
            << ", " << node->public_ip() << ":" << node->public_port << std::endl;
    }
}

void Command::Help() {
    std::cout << "Allowed options:" << std::endl;
    std::cout << "\t-h [help]            print help info" << std::endl;
    std::cout << "\t-c [conf]            set config path" << std::endl;
    std::cout << "\t-v [version]         get bin version" << std::endl;
    std::cout << "\t-g [show_cmd]        show command" << std::endl;
    std::cout << "\t-p [peer]            bootstrap peer ip:port" << std::endl;
    std::cout << "\t-f [first]           1: first node 0: no" << std::endl;
    std::cout << "\t-a [address]         local ip" << std::endl;
    std::cout << "\t-l [listen_port]     local port" << std::endl;
    std::cout << "\t-d [db]              db path" << std::endl;
    std::cout << "\t-o [country]         country code" << std::endl;
    std::cout << "\t-n [network]         network id" << std::endl;
    std::cout << "\t-L [log]             log path" << std::endl;
}

void Command::SendClientUseBandwidth(const std::string& id, uint32_t bandwidth) {
    std::string now_day_timestamp = std::to_string(common::TimeUtils::TimestampDays());
    std::string attr_key = (common::kIncreaseVpnBandwidth + "_" +
        common::Encode::HexEncode(id) + "_" + now_day_timestamp);
    std::map<std::string, std::string> attrs{
        {attr_key, std::to_string(bandwidth)}
    };
    std::string gid;
    client::TransactionClient::Instance()->Transaction(
            id,
            0,
            contract::kContractVpnBandwidthProveAddr,
            attrs,
            common::kConsensusVpnBandwidth,
            gid);
}

void Command::LevelDbToRocksDb(const std::string& db_path) {
#ifndef LEVELDB
//     if (!db::Db::Instance()->Init(db_path)) {
//         std::cout << "fix db open leveldb error." << std::endl;
//         return;
//     }
// 
//     if (!db::Db::Instance()->RocksInit(db_path + "rocks")) {
//         std::cout << "fix db open rocksdb error." << std::endl;
//         return;
//     }
// 
//     auto iter = db::Db::Instance()->db()->NewIterator(leveldb::ReadOptions());
//     for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
//         bft::protobuf::Block block_item;
//         if (!block_item.ParseFromString(iter->value().ToString()) ||
//             !block_item.has_tx_block()) {
//             continue;
//         }
// 
//         db::Db::Instance()->RocksPut(iter->key().ToString(), iter->value().ToString());
//     }
#endif
}

void Command::FixDb(const std::string& db_path) {
    if (!db::Db::Instance()->Init(db_path)) {
        std::cout << "fix db open db error." << std::endl;
        return;
    }

    std::unordered_set<std::string> added_user_set;
    for (uint32_t i = 0; i < common::kInvalidPoolIndex; ++i) {
        std::string key = block::GetLastBlockHash(common::kTestForNetworkId, i);
        std::string last_block_hash;
        auto st = db::Db::Instance()->Get(key, &last_block_hash);
        if (!st.ok()) {
            INIT_ERROR("get last block [%d][%d] error.", common::kTestForNetworkId, i);
            return;
        }

        if (LoadAllTx(last_block_hash, common::kTestForNetworkId, i, added_user_set) != kInitSuccess) {
            INIT_ERROR("load tx from db failed!");
            return;
        }
    }
}

int Command::LoadAllTx(
        const std::string& frist_hash,
        uint32_t netid,
        uint32_t pool_index,
        std::unordered_set<std::string>& added_user_set) {
    std::string tmp_str = frist_hash;
    auto b_time = common::TimeUtils::TimestampMs();
    auto a_b_time = common::TimeUtils::TimestampMs();
    int i = 0;
    std::string block_str;
    std::cout << "load all tx now." << pool_index << std::endl;
    while (true) {
        auto st = db::Db::Instance()->Get(tmp_str, &block_str);
        if (!st.ok()) {
            INIT_ERROR("load block from db failed[%s]",
                common::Encode::HexEncode(tmp_str).c_str());
            return kInitError;
        }

        bft::protobuf::Block block_item;
        if (!block_item.ParseFromString(block_str)) {
            INIT_ERROR("protobuf::Block ParseFromString failed!");
            return kInitError;
        }

        for (int i = 0; i < block_item.tx_list_size(); ++i) {
            std::string accout_id;
            if (block_item.tx_list(i).to_add()) {
                accout_id = block_item.tx_list(i).to();
            } else {
                accout_id = block_item.tx_list(i).from();
            }

            if (block_item.tx_list(i).balance() > 0) {
                auto iter = added_user_set.find(accout_id);
                if (iter == added_user_set.end()) {
                    added_user_set.insert(accout_id);
                    printf("get account[%s] balance[%lu]\n",
                        common::Encode::HexEncode(accout_id).c_str(),
                        block_item.tx_list(i).balance());
                }
            }
        }

        tmp_str = block_item.prehash();
        if (tmp_str.empty()) {
            break;
        }
    }

    return kInitSuccess;
}

int Command::LoadAllNodesAndCheckPort() {
    common::Config conf;
    if (conf.Init("./conf/tenon.conf")) {
        std::cout << "init conf failed!" << std::endl;
        return kInitError;
    }

    std::string config_nodes;
    conf.Get("tenon", "config_nodes", config_nodes);
    if (!config_nodes.empty()) {
        common::Split<1024> nodes_split(config_nodes.c_str(), ',', config_nodes.size());
        for (uint32_t i = 0; i < nodes_split.Count(); ++i) {
            common::Split<> tmp_split(nodes_split[i], ':', nodes_split.SubLen(i));
            std::string pub_key = common::Encode::HexDecode(tmp_split[1]);
            auto account_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pub_key);
            auto country = ip::IpWithCountry::Instance()->GetCountryCode(tmp_split[0]);
            auto country_code = common::global_country_map[country];
            auto dht_key_mgr = dht::DhtKeyManager(
                network::kVpnNetworkId,
                country_code,
                account_id);
            auto dht_key = dht_key_mgr.StrKey();
            uint16_t port = common::GetVpnServerPort(
                common::Encode::HexDecode(dht_key),
                common::TimeUtils::TimestampDays(),
                0,
                0);
            config_node_info_.push_back({
                    country,
                    tmp_split[0],
                    pub_key,
                    dht_key,
                    port });
            config_node_ips_.insert(tmp_split[0]);
        }
    }

    return 0;
}

int Command::CheckAllNodePortValid() {
    for (auto iter = config_node_info_.begin(); iter != config_node_info_.end(); ++iter) {
        bool reacheable = false;
        common::RemoteReachable((*iter).ip, (*iter).vpn_port, &reacheable);
        if (!reacheable) {
            std::cout << "node can't reachable: " << (*iter).ip << ":" << (*iter).vpn_port << std::endl;
        }
    }

    return 0;
}

int Command::PrivateKeyToPublicKey(const std::string& file) {
    FILE* fp = fopen(file.c_str(), "r");
    if (fp == nullptr) {
        return kInitError;
    }

    char data[1024] = { 0 };
    FILE* out = fopen("./out", "w");
    if (out == nullptr) {
        return kInitError;
    }

    while (fgets(data, 1024, fp) != nullptr) {
        data[64] = '\0';
        security::PrivateKey prikey(common::Encode::HexDecode(data));
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        pubkey.Serialize(pubkey_str, true);
        fputs((std::string(data) + "\t" + common::Encode::HexEncode(pubkey_str) + "\n").c_str(), out);
    }

    fclose(fp);
    return kInitSuccess;
}

std::string Command::CreateContractBallot() {
    // create voter
    std::vector<std::string> voters = {
        "544064949151817a1185e931ea43a71493f9f33c",
        "15518b7643b094a6b1faba3a91fc16c20a9041da",
        "7c4fd7e97e3cdd18dbe56e1256fbd60d4129af66",
        "7027d87b3b251eac11933b5c2e4bd2ff1f7dd666",
        "a2234d38e7073639156ee1cfc323e8d6cdadc604",
        "2935aeb958731e29b8297d7250903b86c22b40be",
        "14f87c1026d307937b6160ca69b24e891467749b",
        "4dca4186ec80fe5bbce7531186fc8966d8dd58a9",
        "a45c90f01155cd8615d2db4267b6ee0e8e3d6528",
        "cc686eefa301ec1a781a77a915a742cc5f562613",
    };

    std::string gid;
    for (auto iter = voters.begin(); iter != voters.end(); ++iter) {
        client::VpnClient::Instance()->Transaction(
            *iter,
            10000000000lu,
            gid);
    }

    // create contract
    static const std::string bytes_code = common::Encode::HexDecode(std::string("6080604052348015620000125760006000fd5b506040516200156338038062001563833981810160405281019062000038919062000299565b5b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600160016000506000600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000506000016000508190909055506000600090505b8151811015620001ca576002600050604051806040016040528084848151811015156200014c577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101516000191681526020016000815260200150908060018154018082558091505060019003906000526020600020906002020160005b909190919091506000820151816000016000509060001916905560208201518160010160005090905550505b8080620001c19062000389565b915050620000f6565b505b506200046b566200046a565b6000620001ef620001e9846200030c565b620002e1565b90508083825260208201905082856020860282011115620002105760006000fd5b60005b8581101562000245578162000229888262000281565b8452602084019350602083019250505b60018101905062000213565b5050505b9392505050565b600082601f8301121515620002655760006000fd5b815162000277848260208601620001d8565b9150505b92915050565b60008151905062000292816200044c565b5b92915050565b600060208284031215620002ad5760006000fd5b600082015167ffffffffffffffff811115620002c95760006000fd5b620002d78482850162000250565b9150505b92915050565b6000620002ed62000301565b9050620002fb828262000352565b5b919050565b600060405190505b90565b600067ffffffffffffffff8211156200032a576200032962000409565b5b6020820290506020810190505b919050565b60008190505b919050565b60008190505b919050565b6200035d826200043a565b810181811067ffffffffffffffff821117156200037f576200037e62000409565b5b806040525050505b565b6000620003968262000347565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415620003cc57620003cb620003d8565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b62000457816200033c565b81141515620004665760006000fd5b505b565b5b6110e8806200047b6000396000f3fe60806040523480156100115760006000fd5b506004361061008d5760003560e01c8063609ff1bd1161005c578063609ff1bd1461011a5780639e7b8d6114610138578063a3ec138d14610154578063e2ba53f0146101875761008d565b80630121b93f14610093578063013cf08b146100af5780632e4176cf146100e05780635c19a95c146100fe5761008d565b60006000fd5b6100ad60048036038101906100a89190610b51565b6101a5565b005b6100c960048036038101906100c49190610b51565b6102e8565b6040516100d7929190610ccc565b60405180910390f35b6100e8610326565b6040516100f59190610c94565b60405180910390f35b61011860048036038101906101139190610b26565b61034c565b005b61012261074b565b60405161012f9190610dbc565b60405180910390f35b610152600480360381019061014d9190610b26565b610845565b005b61016e60048036038101906101699190610b26565b610a21565b60405161017e9493929190610dd8565b60405180910390f35b61018f610a87565b60405161019c9190610cb0565b60405180910390f35b6000600160005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff16151515610242576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161023990610cf6565b60405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020160005081909090555080600001600050546002600050838154811015156102b4577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600082828250546102da9190610e30565b925050819090905550505b50565b600260005081815481106102fb57600080fd5b906000526020600020906002020160005b915090508060000160005054908060010160005054905082565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff161515156103e9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103e090610d17565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415151561045a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161045190610d9b565b60405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160005060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415156105dc57600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16915081503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141515156105d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105ce90610d59565b60405180910390fd5b61045b565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160005060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff161561071e578160000160005054600260005082600201600050548154811015156106ea577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600082828250546107109190610e30565b925050819090905550610745565b8160000160005054816000016000828282505461073b9190610e30565b9250508190909055505b50505b50565b60006000600090506000600090505b60026000508054905081101561083f57816002600050828154811015156107aa577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b5060010160005054111561082b57600260005081815481101515610808577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600050549150815080925082505b5b808061083790610ede565b91505061075a565b50505b90565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156108d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108ce90610d38565b60405180910390fd5b600160005060008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160009054906101000a900460ff1615151561096f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161096690610d7a565b60405180910390fd5b6000600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050600001600050541415156109ca5760006000fd5b6001600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000506000016000508190909055505b50565b60016000506020528060005260406000206000915090508060000160005054908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160005054905084565b60006002600050610a9c61074b63ffffffff16565b815481101515610ad5577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b5060000160005054905080505b90566110b1565b600081359050610b098161107b565b5b92915050565b600081359050610b1f81611096565b5b92915050565b600060208284031215610b395760006000fd5b6000610b4784828501610afa565b9150505b92915050565b600060208284031215610b645760006000fd5b6000610b7284828501610b10565b9150505b92915050565b610b8581610e87565b825250505b565b610b9581610e9a565b825250505b565b610ba581610ea7565b825250505b565b6000610bb9600e83610e1e565b9150610bc482610f59565b6020820190505b919050565b6000610bdd601283610e1e565b9150610be882610f83565b6020820190505b919050565b6000610c01602883610e1e565b9150610c0c82610fad565b6040820190505b919050565b6000610c25601983610e1e565b9150610c3082610ffd565b6020820190505b919050565b6000610c49601883610e1e565b9150610c5482611027565b6020820190505b919050565b6000610c6d601e83610e1e565b9150610c7882611051565b6020820190505b919050565b610c8d81610ed3565b825250505b565b6000602082019050610ca96000830184610b7c565b5b92915050565b6000602082019050610cc56000830184610b9c565b5b92915050565b6000604082019050610ce16000830185610b9c565b610cee6020830184610c84565b5b9392505050565b60006020820190508181036000830152610d0f81610bac565b90505b919050565b60006020820190508181036000830152610d3081610bd0565b90505b919050565b60006020820190508181036000830152610d5181610bf4565b90505b919050565b60006020820190508181036000830152610d7281610c18565b90505b919050565b60006020820190508181036000830152610d9381610c3c565b90505b919050565b60006020820190508181036000830152610db481610c60565b90505b919050565b6000602082019050610dd16000830184610c84565b5b92915050565b6000608082019050610ded6000830187610c84565b610dfa6020830186610b8c565b610e076040830185610b7c565b610e146060830184610c84565b5b95945050505050565b60008282526020820190505b92915050565b6000610e3b82610ed3565b9150610e4683610ed3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610e7b57610e7a610f28565b5b82820190505b92915050565b6000610e9282610eb2565b90505b919050565b600081151590505b919050565b60008190505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b6000610ee982610ed3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415610f1c57610f1b610f28565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f416c726561647920766f7465642e0000000000000000000000000000000000006000820152505b565b7f596f7520616c726561647920766f7465642e00000000000000000000000000006000820152505b565b7f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742060008201527f746f20766f74652e0000000000000000000000000000000000000000000000006020820152505b565b7f466f756e64206c6f6f7020696e2064656c65676174696f6e2e000000000000006000820152505b565b7f54686520766f74657220616c726561647920766f7465642e00000000000000006000820152505b565b7f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e00006000820152505b565b61108481610e87565b811415156110925760006000fd5b505b565b61109f81610ed3565b811415156110ad5760006000fd5b505b565bfea26469706673582212203e5565408852e1106e62e1583e3a4bbb4a5239bce40f4a6001872942cd6b097364736f6c63430008040033") + "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8704348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8701348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8702");
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(bytes_code, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::ChairmanSetVoters(const std::string& contract_addr) {
    std::vector<std::string> voters = {
        "544064949151817a1185e931ea43a71493f9f33c",
        "15518b7643b094a6b1faba3a91fc16c20a9041da",
        "7c4fd7e97e3cdd18dbe56e1256fbd60d4129af66",
        "7027d87b3b251eac11933b5c2e4bd2ff1f7dd666",
        "a2234d38e7073639156ee1cfc323e8d6cdadc604",
        "2935aeb958731e29b8297d7250903b86c22b40be",
        "14f87c1026d307937b6160ca69b24e891467749b",
        "4dca4186ec80fe5bbce7531186fc8966d8dd58a9",
        "a45c90f01155cd8615d2db4267b6ee0e8e3d6528",
        "cc686eefa301ec1a781a77a915a742cc5f562613",
    };

    for (auto iter = voters.begin(); iter != voters.end(); ++iter) {
        std::map<std::string, std::string> attrs;
        attrs[bft::kContractInputCode] = common::Encode::HexDecode("9e7b8d61000000000000000000000000" + *iter);
        uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas + (
            bft::kContractInputCode.size() +
            attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
        std::string gid;
        client::VpnClient::Instance()->TransactionEx(
            contract_addr,
            0,
            gas_usd,
            common::kConsensusCallContract,
            attrs,
            gid);
    }
}

void Command::ChairmanSetVoter(const std::string& contract_addr, const std::string& des) {
    // call set voter
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("9e7b8d61000000000000000000000000" + des);
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas + (
        bft::kContractInputCode.size() +
        attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::VoterSetDelegate(const std::string& contract_addr, const std::string& dest) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("5c19a95c000000000000000000000000" + dest);
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas + 
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::Vote(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("0121b93f0000000000000000000000000000000000000000000000000000000000000001");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::GetWinner(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("e2ba53f000000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreateReceivePay() {
    // create voter
    std::string receiver = "544064949151817a1185e931ea43a71493f9f33c";
    std::string gid;
    client::VpnClient::Instance()->Transaction(
        receiver,
        10000000000lu,
        gid);

    // create contract
    static const std::string bytes_code = common::Encode::HexDecode("608060405233600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b5b61004c565b6107538061005b6000396000f3fe60806040523480156100115760006000fd5b506004361061003b5760003560e01c806341c0e1b514610041578063a90ae8871461004b5761003b565b60006000fd5b610049610067565b005b610065600480360381019061006091906103ba565b6100df565b005b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156100c45760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff16ff5b565b6001600050600083815260200190815260200160002060009054906101000a900460ff161515156101105760006000fd5b60016001600050600084815260200190815260200160002060006101000a81548160ff021916908315150217905550600061017c3385853060405160200161015b94939291906104d8565b6040516020818303038152906040528051906020012061023963ffffffff16565b9050600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166101c7828461026e63ffffffff16565b73ffffffffffffffffffffffffffffffffffffffff161415156101ea5760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc859081150290604051600060405180830381858888f19350505050158015610231573d600060003e3d6000fd5b50505b505050565b60008160405160200161024c91906104b1565b604051602081830303815290604052805190602001209050610269565b919050565b6000600060006000610285856102ee63ffffffff16565b925092509250600186848484604051600081526020016040526040516102ae949392919061051e565b6020604051602081039080840390855afa1580156102d1573d600060003e3d6000fd5b5050506020604051035193505050506102e8565050505b92915050565b600060006000604184511415156103055760006000fd5b6020840151915060408401519050606084015160001a925082828292509250925061032b565b91939092505661071c565b60006103496103448461058b565b610564565b9050828152602081018484840111156103625760006000fd5b61036d848285610647565b505b9392505050565b600082601f830112151561038a5760006000fd5b813561039a848260208601610336565b9150505b92915050565b6000813590506103b381610701565b5b92915050565b600060006000606084860312156103d15760006000fd5b60006103df868287016103a4565b93505060206103f0868287016103a4565b925050604084013567ffffffffffffffff81111561040e5760006000fd5b61041a86828701610376565b9150505b9250925092565b61042e816105c9565b825250505b565b61043e816105dc565b825250505b565b610456610451826105dc565b610689565b825250505b565b61046681610621565b825250505b565b600061047a601c836105bd565b9150610485826106d7565b601c820190505b919050565b61049a81610608565b825250505b565b6104aa81610613565b825250505b565b60006104bc8261046d565b91506104c88284610445565b6020820191508190505b92915050565b60006080820190506104ed6000830187610425565b6104fa6020830186610491565b6105076040830185610491565b610514606083018461045d565b5b95945050505050565b60006080820190506105336000830187610435565b61054060208301866104a1565b61054d6040830185610435565b61055a6060830184610435565b5b95945050505050565b600061056e610580565b905061057a8282610657565b5b919050565b600060405190505b90565b600067ffffffffffffffff8211156105a6576105a5610694565b5b6105af826106c5565b90506020810190505b919050565b60008190505b92915050565b60006105d4826105e7565b90505b919050565b60008190505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b600060ff821690505b919050565b600061062c82610634565b90505b919050565b600061063f826105e7565b90505b919050565b828183376000838301525050505b565b610660826106c5565b810181811067ffffffffffffffff8211171561067f5761067e610694565b5b806040525050505b565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b7f19457468657265756d205369676e6564204d6573736167653a0a3332000000006000820152505b565b61070a81610608565b811415156107185760006000fd5b505b565bfea26469706673582212207d24328cffe9c38baa5948249ab1e85c99dac9c1b744eb13246d64d072a40edd64736f6c63430008040033");
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(bytes_code, amount, gas_limit, &contract_address);
    std::string tx_gid;
    tenon::client::VpnClient::Instance()->Transaction(common::Encode::HexEncode(contract_address), 1000000000lu, tx_gid);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;

    std::string path = R"(
        const Web3 = require('web3')
        var net = require('net');
        var web3 = new Web3(new Web3.providers.IpcProvider('/Users/myuser/Library/Ethereum/geth.ipc', net));
        const args = require('minimist')(process.argv.slice(2))
        var param_codes = web3.eth.abi.encodeParameters(['address', 'uint256', 'uint256', 'address'], ['0x' + args['to'], '2643000', '1', '0x' + args['caddr']]);
        var kek256 = web3.utils.keccak256(param_codes);
        var param_code_hash = web3.eth.accounts.hashMessage(kek256)
        var sig_param = web3.eth.accounts.sign(kek256, '0xf0aed1c9983eec2ae15461057a838663ada156b4540dfd2df96c5bbcef529b6e');
        var receive_pay_params = web3.eth.abi.encodeParameters(['uint256', 'uint256', 'bytes memory'], ['2643000', '1', sig_param.signature]);
        var receive_func = web3.eth.abi.encodeFunctionSignature('claimPayment(uint256,uint256,bytes)');
        var recover = web3.eth.accounts.recover({messageHash: param_code_hash, v: sig_param.v, r: sig_param.r, s: sig_param.s});
        console.log(receive_func.substring(2) + receive_pay_params.substring(2));
        )";
    return contract_address;
}

void Command::ReceivePay(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreateSimpleAuction() {
    // create contract
    static const std::string simple_auction = common::Encode::HexDecode(std::string("6080604052348015620000125760006000fd5b5060405162000c7338038062000c738339818101604052810190620000389190620000d1565b5b80600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550814262000088919062000115565b60016000508190909055505b5050620002225662000221565b600081519050620000b281620001e5565b5b92915050565b600081519050620000ca8162000203565b5b92915050565b6000600060408385031215620000e75760006000fd5b6000620000f785828601620000b9565b92505060206200010a85828601620000a1565b9150505b9250929050565b60006200012282620001a9565b91506200012f83620001a9565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115620001675762000166620001b4565b5b82820190505b92915050565b6000620001808262000188565b90505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b620001f08162000173565b81141515620001ff5760006000fd5b505b565b6200020e81620001a9565b811415156200021d5760006000fd5b505b565b5b610a4180620002326000396000f3fe6080604052600436106100745760003560e01c806338af3eed1161004e57806338af3eed146100c85780633ccfd60b146100f457806391f9015714610120578063d57bde791461014c57610074565b80631998aeef1461007a5780631efd8fa3146100845780632a24f46c146100b057610074565b60006000fd5b610082610178565b005b3480156100915760006000fd5b5061009a610328565b6040516100a79190610827565b60405180910390f35b3480156100bd5760006000fd5b506100c6610331565b005b3480156100d55760006000fd5b506100de6104ba565b6040516100eb9190610741565b60405180910390f35b3480156101015760006000fd5b5061010a6104e0565b6040516101179190610787565b60405180910390f35b34801561012d5760006000fd5b50610136610622565b6040516101439190610725565b60405180910390f35b3480156101595760006000fd5b50610162610648565b60405161016f9190610827565b60405180910390f35b60016000505442111515156101c2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101b9906107a3565b60405180910390fd5b6003600050543411151561020b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610202906107c4565b60405180910390fd5b600060036000505414151561029f5760036000505460046000506000600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082828250546102959190610855565b9250508190909055505b33600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055503460036000508190909055507ff4757a49b326036464bec6fe419a4ae38c8a02ce3e68bf0809674f6aab8ad300333460405161031d92919061075d565b60405180910390a15b565b60016000505481565b600160005054421015151561037b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610372906107e5565b60405180910390fd5b600560009054906101000a900460ff161515156103cd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103c490610806565b60405180910390fd5b6001600560006101000a81548160ff0219169083151502179055507fdaec4582d5d9595688c8c98545fdd1c696d41c6aeaeb636737e84ed2f5c00eda600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1660036000505460405161044092919061075d565b60405180910390a1600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc6003600050549081150290604051600060405180830381858888f193505050501580156104b6573d600060003e3d6000fd5b505b565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60006000600460005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000505490506000811115610614576000600460005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000508190909055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f1935050505015156106135780600460005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050819090905550600091505061061f565b5b600191505061061f56505b90565b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6003600050548156610a0a565b61065e816108bf565b825250505b565b61066e816108ac565b825250505b565b61067e816108d2565b825250505b565b6000610692601683610843565b915061069d8261093c565b6020820190505b919050565b60006106b6601e83610843565b91506106c182610966565b6020820190505b919050565b60006106da601683610843565b91506106e582610990565b6020820190505b919050565b60006106fe602583610843565b9150610709826109ba565b6040820190505b919050565b61071e81610900565b825250505b565b600060208201905061073a6000830184610665565b5b92915050565b60006020820190506107566000830184610655565b5b92915050565b60006040820190506107726000830185610665565b61077f6020830184610715565b5b9392505050565b600060208201905061079c6000830184610675565b5b92915050565b600060208201905081810360008301526107bc81610685565b90505b919050565b600060208201905081810360008301526107dd816106a9565b90505b919050565b600060208201905081810360008301526107fe816106cd565b90505b919050565b6000602082019050818103600083015261081f816106f1565b90505b919050565b600060208201905061083c6000830184610715565b5b92915050565b60008282526020820190505b92915050565b600061086082610900565b915061086b83610900565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156108a05761089f61090b565b5b82820190505b92915050565b60006108b7826108df565b90505b919050565b60006108ca826108df565b90505b919050565b600081151590505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f41756374696f6e20616c726561647920656e6465642e000000000000000000006000820152505b565b7f546865726520616c7265616479206973206120686967686572206269642e00006000820152505b565b7f41756374696f6e206e6f742079657420656e6465642e000000000000000000006000820152505b565b7f61756374696f6e456e64546d2068617320616c7265616479206265656e20636160008201527f6c6c65642e0000000000000000000000000000000000000000000000000000006020820152505b565bfea2646970667358221220ed8105d62b19df06a196dbc1d0ac051c9c206b5f099949174f9d5a52c20b82b164736f6c63430008040033") + "00000000000000000000000000000000000000000000000000000000000003e800000000000000000000000015518b7643b094a6b1faba3a91fc16c20a9041da");
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(simple_auction, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::SimpleAuctionBid(const std::string& contract_addr, uint64_t amount) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("1998aeef00000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        amount,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::SimpleAuctionWithDraw(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("3ccfd60b00000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::SimpleAuctionEnd(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("2a24f46c00000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreateBlindAuction() {
    // create contract
    static const std::string blind_auction = common::Encode::HexDecode(std::string("6080604052348015620000125760006000fd5b50604051620014c0380380620014c08339818101604052810190620000389190620000f0565b5b80600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550824262000088919062000149565b600160005081909090555081600160005054620000a6919062000149565b60026000508190909055505b505050620002565662000255565b600081519050620000d18162000219565b5b92915050565b600081519050620000e98162000237565b5b92915050565b60006000600060608486031215620001085760006000fd5b60006200011886828701620000d8565b93505060206200012b86828701620000d8565b92505060406200013e86828701620000c0565b9150505b9250925092565b60006200015682620001dd565b91506200016383620001dd565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156200019b576200019a620001e8565b5b82820190505b92915050565b6000620001b482620001bc565b90505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b6200022481620001a7565b81141515620002335760006000fd5b505b565b6200024281620001dd565b81141515620002515760006000fd5b505b565b5b61125a80620002666000396000f3fe6080604052600436106100a05760003560e01c8063423b217f11610064578063423b217f1461016d578063900f080a1461019957806391f90157146101c3578063957bb1e0146101ef578063a6e664771461020b578063d57bde7914610237576100a0565b806301495c1c146100a657806312fa6feb146100e55780632a24f46c1461011157806338af3eed146101295780633ccfd60b14610155576100a0565b60006000fd5b3480156100b35760006000fd5b506100ce60048036038101906100c99190610cd0565b610263565b6040516100dc929190610ea5565b60405180910390f35b3480156100f25760006000fd5b506100fb6102b1565b6040516101089190610e89565b60405180910390f35b34801561011e5760006000fd5b506101276102c4565b005b3480156101365760006000fd5b5061013f6103e5565b60405161014c9190610e43565b60405180910390f35b3480156101625760006000fd5b5061016b61040b565b005b34801561017a5760006000fd5b506101836104f8565b6040516101909190610ecf565b60405180910390f35b3480156101a65760006000fd5b506101c160048036038101906101bc9190610d0f565b610501565b005b3480156101d05760006000fd5b506101d9610849565b6040516101e69190610e27565b60405180910390f35b61020960048036038101906102049190610dac565b61086f565b005b3480156102185760006000fd5b50610221610939565b60405161022e9190610ecf565b60405180910390f35b3480156102445760006000fd5b5061024d610942565b60405161025a9190610ecf565b60405180910390f35b6004600050602052816000526040600020600050818154811061028557600080fd5b906000526020600020906002020160005b91509150508060000160005054908060010160005054905082565b600360009054906101000a900460ff1681565b60026000505480421115156102d95760006000fd5b600360009054906101000a900460ff161515156102f65760006000fd5b7fdaec4582d5d9595688c8c98545fdd1c696d41c6aeaeb636737e84ed2f5c00eda600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1660066000505460405161034e929190610e5f565b60405180910390a16001600360006101000a81548160ff021916908315150217905550600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc6006600050549081150290604051600060405180830381858888f193505050501580156103df573d600060003e3d6000fd5b505b5b50565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600760005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005054905060008111156104f4576000600760005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000508190909055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501580156104f2573d600060003e3d6000fd5b505b505b565b60016000505481565b60016000505480421115156105165760006000fd5b600260005054804210151561052b5760006000fd5b6000600460005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000508054905090508086511415156105885760006000fd5b8085511415156105985760006000fd5b8084511415156105a85760006000fd5b60006000600090505b828110156107f4576000600460005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000508281548110151561063a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b5090506000600060008b8581518110151561068f577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101518b868151811015156106d2577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101518b87815181101515610715577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015192509250925082828260405160200161073893929190610eeb565b604051602081830303815290604052805190602001206000191684600001600050546000191614151561076e57505050506107e1565b8360010160005054866107819190610fd1565b955085508115801561079a575082846001016000505410155b156107c6576107af338461094b63ffffffff16565b156107c55782866107c09190611028565b955085505b5b600060001b8460000160005081909060001916905550505050505b80806107ec906110f9565b9150506105b1565b503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f1935050505015801561083c573d600060003e3d6000fd5b5050505b5b505b50505050565b600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60016000505480421015156108845760006000fd5b600460005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060405180604001604052808460001916815260200134815260200150908060018154018082558091505060019003906000526020600020906002020160005b909190919091506000820151816000016000509060001916905560208201518160010160005090905550505b5b5050565b60026000505481565b60066000505481565b6000600660005054821115156109645760009050610a97565b600073ffffffffffffffffffffffffffffffffffffffff16600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16141515610a415760066000505460076000506000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282825054610a379190610fd1565b9250508190909055505b81600660005081909090555082600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060019050610a97565b9291505056611223565b6000610ab4610aaf84610f4a565b610f23565b90508083825260208201905082856020860282011115610ad45760006000fd5b60005b85811015610b055781610aea8882610c8e565b8452602084019350602083019250505b600181019050610ad7565b5050505b9392505050565b6000610b23610b1e84610f77565b610f23565b90508083825260208201905082856020860282011115610b435760006000fd5b60005b85811015610b745781610b598882610ca4565b8452602084019350602083019250505b600181019050610b46565b5050505b9392505050565b6000610b92610b8d84610fa4565b610f23565b90508083825260208201905082856020860282011115610bb25760006000fd5b60005b85811015610be35781610bc88882610cba565b8452602084019350602083019250505b600181019050610bb5565b5050505b9392505050565b600081359050610bfd816111b7565b5b92915050565b600082601f8301121515610c185760006000fd5b8135610c28848260208601610aa1565b9150505b92915050565b600082601f8301121515610c465760006000fd5b8135610c56848260208601610b10565b9150505b92915050565b600082601f8301121515610c745760006000fd5b8135610c84848260208601610b7f565b9150505b92915050565b600081359050610c9d816111d2565b5b92915050565b600081359050610cb3816111ed565b5b92915050565b600081359050610cc981611208565b5b92915050565b6000600060408385031215610ce55760006000fd5b6000610cf385828601610bee565b9250506020610d0485828601610cba565b9150505b9250929050565b60006000600060608486031215610d265760006000fd5b600084013567ffffffffffffffff811115610d415760006000fd5b610d4d86828701610c60565b935050602084013567ffffffffffffffff811115610d6b5760006000fd5b610d7786828701610c04565b925050604084013567ffffffffffffffff811115610d955760006000fd5b610da186828701610c32565b9150505b9250925092565b600060208284031215610dbf5760006000fd5b6000610dcd84828501610ca4565b9150505b92915050565b610de081611070565b825250505b565b610df08161105d565b825250505b565b610e0081611083565b825250505b565b610e1081611090565b825250505b565b610e20816110bc565b825250505b565b6000602082019050610e3c6000830184610de7565b5b92915050565b6000602082019050610e586000830184610dd7565b5b92915050565b6000604082019050610e746000830185610de7565b610e816020830184610e17565b5b9392505050565b6000602082019050610e9e6000830184610df7565b5b92915050565b6000604082019050610eba6000830185610e07565b610ec76020830184610e17565b5b9392505050565b6000602082019050610ee46000830184610e17565b5b92915050565b6000606082019050610f006000830186610e17565b610f0d6020830185610df7565b610f1a6040830184610e07565b5b949350505050565b6000610f2d610f3f565b9050610f3982826110c7565b5b919050565b600060405190505b90565b600067ffffffffffffffff821115610f6557610f64611174565b5b6020820290506020810190505b919050565b600067ffffffffffffffff821115610f9257610f91611174565b5b6020820290506020810190505b919050565b600067ffffffffffffffff821115610fbf57610fbe611174565b5b6020820290506020810190505b919050565b6000610fdc826110bc565b9150610fe7836110bc565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561101c5761101b611143565b5b82820190505b92915050565b6000611033826110bc565b915061103e836110bc565b92508282101561105157611050611143565b5b82820390505b92915050565b60006110688261109b565b90505b919050565b600061107b8261109b565b90505b919050565b600081151590505b919050565b60008190505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b6110d0826111a5565b810181811067ffffffffffffffff821117156110ef576110ee611174565b5b806040525050505b565b6000611104826110bc565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82141561113757611136611143565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b6111c08161105d565b811415156111ce5760006000fd5b505b565b6111db81611083565b811415156111e95760006000fd5b505b565b6111f681611090565b811415156112045760006000fd5b505b565b611211816110bc565b8114151561121f5760006000fd5b505b565bfea2646970667358221220cfe1d919911f5f207ae31fa0423c70acaead304e788c5ee4fec0597a0e2bbf0764736f6c63430008040033") + "000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000006400000000000000000000000015518b7643b094a6b1faba3a91fc16c20a9041da");
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(blind_auction, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::BlindAuctionBit(const std::string& contract_addr, const std::string& blindBid, uint64_t amount) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = blindBid;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        amount,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::BlindAuctionReveal(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::BlindAuctionWithdraw(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("3ccfd60b00000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::BlindAuctionEnd(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("2a24f46c00000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreatePurchase() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("60806040525b33600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060023462000055919062000123565b60006000508190909055503460006000505460026200007591906200015e565b141515620000ba576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401620000b190620000ee565b60405180910390fd5b5b620002585662000257565b6000620000d560158362000111565b9150620000e2826200022d565b6020820190505b919050565b600060208201905081810360008301526200010981620000c6565b90505b919050565b60008282526020820190505b92915050565b60006200013082620001c0565b91506200013d83620001c0565b9250821515620001525762000151620001fc565b5b82820490505b92915050565b60006200016b82620001c0565b91506200017883620001c0565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615620001b457620001b3620001cb565b5b82820290505b92915050565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b565b7f56616c75652068617320746f206265206576656e2e00000000000000000000006000820152505b565b5b610dd480620002686000396000f3fe60806040526004361061007f5760003560e01c806373fac6f01161004e57806373fac6f014610121578063c19d93fb14610139578063c7981b1b14610165578063d69606971461017d5761007f565b806308551a531461008557806335a063b4146100b15780633fa4f245146100c95780637150d8ae146100f55761007f565b60006000fd5b3480156100925760006000fd5b5061009b610187565b6040516100a89190610b1c565b60405180910390f35b3480156100be5760006000fd5b506100c76101ad565b005b3480156100d65760006000fd5b506100df6103f1565b6040516100ec9190610bb7565b60405180910390f35b3480156101025760006000fd5b5061010b6103fa565b6040516101189190610b1c565b60405180910390f35b34801561012e5760006000fd5b50610137610420565b005b3480156101465760006000fd5b5061014f610669565b60405161015c9190610b38565b60405180910390f35b3480156101725760006000fd5b5061017b61067c565b005b6101856108d1565b005b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561023f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161023690610b96565b60405180910390fd5b600080600381111561027a577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b600260149054906101000a900460ff1660038111156102c2577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b141515610304576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102fb90610b75565b60405180910390fd5b7f72c874aeff0b183a56e2b79c71b46e1aed4dee5e09862134b8821ba2fddbf8bf60405160405180910390a16003600260146101000a81548160ff0219169083600381111561037c577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b0217905550600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f193505050501580156103ea573d600060003e3d6000fd5b505b5b505b565b60006000505481565b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156104b2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104a990610b54565b60405180910390fd5b60018060038111156104ed577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b600260149054906101000a900460ff166003811115610535577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b141515610577576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161056e90610b75565b60405180910390fd5b7fe89152acd703c9d8c7d28829d443260b411454d45394e7995815140c8cbcbcf760405160405180910390a16002600260146101000a81548160ff021916908360038111156105ef577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b0217905550600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc6000600050549081150290604051600060405180830381858888f19350505050158015610662573d600060003e3d6000fd5b505b5b505b565b600260149054906101000a900460ff1681565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561070e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161070590610b96565b60405180910390fd5b6002806003811115610749577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b600260149054906101000a900460ff166003811115610791577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b1415156107d3576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107ca90610b75565b60405180910390fd5b7ffda69c32bcfdba840a167777906b173b607eb8b4d8853b97a80d26e613d858db60405160405180910390a16003600260146101000a81548160ff0219169083600381111561084b577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b0217905550600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc600060005054600361089e9190610be5565b9081150290604051600060405180830381858888f193505050501580156108ca573d600060003e3d6000fd5b505b5b505b565b600080600381111561090c577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b600260149054906101000a900460ff166003811115610954577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b141515610996576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161098d90610b75565b60405180910390fd5b60006000505460026109a89190610be5565b34148015156109b75760006000fd5b7fd5d55c8a68912e9a110618df8d5e2e83b8d83211c57a8ddd1203df92885dc88160405160405180910390a133600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506001600260146101000a81548160ff02191690836003811115610a70577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b02179055505b5b505b5056610d9d565b610a8981610c40565b825250505b565b610a9981610c93565b825250505b565b6000610aad601983610bd3565b9150610ab882610d08565b6020820190505b919050565b6000610ad1600e83610bd3565b9150610adc82610d32565b6020820190505b919050565b6000610af5601a83610bd3565b9150610b0082610d5c565b6020820190505b919050565b610b1581610c88565b825250505b565b6000602082019050610b316000830184610a80565b5b92915050565b6000602082019050610b4d6000830184610a90565b5b92915050565b60006020820190508181036000830152610b6d81610aa0565b90505b919050565b60006020820190508181036000830152610b8e81610ac4565b90505b919050565b60006020820190508181036000830152610baf81610ae8565b90505b919050565b6000602082019050610bcc6000830184610b0c565b5b92915050565b60008282526020820190505b92915050565b6000610bf082610c88565b9150610bfb83610c88565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615610c3457610c33610ca6565b5b82820290505b92915050565b6000610c4b82610c67565b90505b919050565b6000819050610c6182610d86565b5b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b6000610c9e82610c53565b90505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b565b7f4f6e6c792062757965722063616e2063616c6c20746869732e000000000000006000820152505b565b7f496e76616c69642073746174652e0000000000000000000000000000000000006000820152505b565b7f4f6e6c792073656c6c65722063616e2063616c6c20746869732e0000000000006000820152505b565b600481101515610d9957610d98610cd7565b5b505b565bfea26469706673582212201d9a331da07bfe41fd110a3025eb3d0eb380bee3cb5d6457fd4c847d5f23092764736f6c63430008040033"));
    uint64_t amount = 1000000000;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::PurchaseAbort(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("35a063b400000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::PurchaseConfirmPurchase(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("d696069700000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        1000000000,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::PurchaseConfirmReceived(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("73fac6f000000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::PurchaseRefundSeller(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("c7981b1b00000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreatePaymentChannel() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("608060405260405162000bb138038062000bb1833981810160405281019062000029919062000103565b5b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555081600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508042620000ba919062000147565b60026000508190909055505b5050620002545662000253565b600081519050620000e48162000217565b5b92915050565b600081519050620000fc8162000235565b5b92915050565b6000600060408385031215620001195760006000fd5b60006200012985828601620000d3565b92505060206200013c85828601620000eb565b9150505b9250929050565b60006200015482620001db565b91506200016183620001db565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115620001995762000198620001e6565b5b82820190505b92915050565b6000620001b282620001ba565b90505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b6200022281620001a5565b81141515620002315760006000fd5b505b565b6200024081620001db565b811415156200024f5760006000fd5b505b565b5b61094d80620002646000396000f3fe60806040523480156100115760006000fd5b50600436106100675760003560e01c80630e1da6c31461006d578063415ffba7146100775780634665096d1461009357806366d003ac146100b157806367e404ce146100cf5780639714378c146100ed57610067565b60006000fd5b610075610109565b005b610091600480360381019061008c91906105ab565b61015b565b005b61009b61027d565b6040516100a89190610742565b60405180910390f35b6100b9610286565b6040516100c691906106b6565b60405180910390f35b6100d76102ac565b6040516100e491906106b6565b60405180910390f35b61010760048036038101906101029190610580565b6102d2565b005b600260005054421015151561011e5760006000fd5b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156101b85760006000fd5b6101c8828261035363ffffffff16565b15156101d45760006000fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc839081150290604051600060405180830381858888f1935050505015801561023d573d600060003e3d6000fd5b50600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b5050565b60026000505481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561032f5760006000fd5b600260005054811115156103435760006000fd5b8060026000508190909055505b50565b6000600061038e308560405160200161036d929190610718565b604051602081830303815290604052805190602001206103ff63ffffffff16565b9050600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166103d9828561043463ffffffff16565b73ffffffffffffffffffffffffffffffffffffffff16149150506103f956505b92915050565b600081604051602001610412919061068f565b60405160208183030381529060405280519060200120905061042f565b919050565b600060006000600061044b856104b463ffffffff16565b9250925092506001868484846040516000815260200160405260405161047494939291906106d2565b6020604051602081039080840390855afa158015610497573d600060003e3d6000fd5b5050506020604051035193505050506104ae565050505b92915050565b600060006000604184511415156104cb5760006000fd5b6020840151915060408401519050606084015160001a92508282829250925092506104f1565b919390925056610916565b600061050f61050a84610785565b61075e565b9050828152602081018484840111156105285760006000fd5b610533848285610841565b505b9392505050565b600082601f83011215156105505760006000fd5b81356105608482602086016104fc565b9150505b92915050565b600081359050610579816108fb565b5b92915050565b6000602082840312156105935760006000fd5b60006105a18482850161056a565b9150505b92915050565b60006000604083850312156105c05760006000fd5b60006105ce8582860161056a565b925050602083013567ffffffffffffffff8111156105ec5760006000fd5b6105f88582860161053c565b9150505b9250929050565b61060c816107c3565b825250505b565b61061c816107d6565b825250505b565b61063461062f826107d6565b610883565b825250505b565b6106448161081b565b825250505b565b6000610658601c836107b7565b9150610663826108d1565b601c820190505b919050565b61067881610802565b825250505b565b6106888161080d565b825250505b565b600061069a8261064b565b91506106a68284610623565b6020820191508190505b92915050565b60006020820190506106cb6000830184610603565b5b92915050565b60006080820190506106e76000830187610613565b6106f4602083018661067f565b6107016040830185610613565b61070e6060830184610613565b5b95945050505050565b600060408201905061072d600083018561063b565b61073a602083018461066f565b5b9392505050565b6000602082019050610757600083018461066f565b5b92915050565b600061076861077a565b90506107748282610851565b5b919050565b600060405190505b90565b600067ffffffffffffffff8211156107a05761079f61088e565b5b6107a9826108bf565b90506020810190505b919050565b60008190505b92915050565b60006107ce826107e1565b90505b919050565b60008190505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b600060ff821690505b919050565b60006108268261082e565b90505b919050565b6000610839826107e1565b90505b919050565b828183376000838301525050505b565b61085a826108bf565b810181811067ffffffffffffffff821117156108795761087861088e565b5b806040525050505b565b60008190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b7f19457468657265756d205369676e6564204d6573736167653a0a3332000000006000820152505b565b61090481610802565b811415156109125760006000fd5b505b565bfea2646970667358221220deed56cee836f9165e5318346956fe9c59536bb4b2f3ffc255f19f1b1a1595d964736f6c63430008040033") + "000000000000000000000000544064949151817a1185e931ea43a71493f9f33c0000000000000000000000000000000000000000000000000000000000000064");
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, 0, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::ChannelClose(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::ChannelExtend(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("9714378c0000000000000000000000000000000000000000000000000000000000000064");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::ChannelClaimTimeout(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("0e1da6c300000000000000000000000000000000000000000000000000000000");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreateToken() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("608060405233600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555034600080600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610aa3806100b96000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c8063095ea7b3146100675780630ecaea731461009757806323b872dd146100c757806367e404ce146100f757806370a0823114610115578063a9059cbb14610145575b600080fd5b610081600480360381019061007c91906107bb565b610175565b60405161008e9190610816565b60405180910390f35b6100b160048036038101906100ac91906107bb565b6102fb565b6040516100be9190610816565b60405180910390f35b6100e160048036038101906100dc9190610831565b61034a565b6040516100ee9190610816565b60405180910390f35b6100ff6104c6565b60405161010c91906108a5565b60405180910390f35b61012f600480360381019061012a91906108c0565b6104ec565b60405161013c91906108fc565b60405180910390f35b61015f600480360381019061015a91906107bb565b610534565b60405161016c9190610816565b60405180910390f35b600080600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414610235576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161022c9061094e565b60405180910390fd5b81600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055507f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9253384846040516102e99392919061097d565b60405180910390a16001905092915050565b6000816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506001905092915050565b600081600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156103d557600080fd5b81600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825461046191906109e3565b925050819055506104808484846000610593909392919063ffffffff16565b7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef8484846040516104b39392919061097d565b60405180910390a1600190509392505050565b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b600061054e3384846000610593909392919063ffffffff16565b7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef3384846040516105819392919061097d565b60405180910390a16001905092915050565b808460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156105de57600080fd5b8360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054818560008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546106679190610a17565b101561067257600080fd5b808460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546106c091906109e3565b92505081905550808460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546107159190610a17565b9250508190555050505050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061075282610727565b9050919050565b61076281610747565b811461076d57600080fd5b50565b60008135905061077f81610759565b92915050565b6000819050919050565b61079881610785565b81146107a357600080fd5b50565b6000813590506107b58161078f565b92915050565b600080604083850312156107d2576107d1610722565b5b60006107e085828601610770565b92505060206107f1858286016107a6565b9150509250929050565b60008115159050919050565b610810816107fb565b82525050565b600060208201905061082b6000830184610807565b92915050565b60008060006060848603121561084a57610849610722565b5b600061085886828701610770565b935050602061086986828701610770565b925050604061087a868287016107a6565b9150509250925092565b600061088f82610727565b9050919050565b61089f81610884565b82525050565b60006020820190506108ba6000830184610896565b92915050565b6000602082840312156108d6576108d5610722565b5b60006108e484828501610770565b91505092915050565b6108f681610785565b82525050565b600060208201905061091160008301846108ed565b92915050565b600082825260208201905092915050565b50565b6000610938600083610917565b915061094382610928565b600082019050919050565b600060208201905081810360008301526109678161092b565b9050919050565b61097781610747565b82525050565b6000606082019050610992600083018661096e565b61099f602083018561096e565b6109ac60408301846108ed565b949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006109ee82610785565b91506109f983610785565b925082821015610a0c57610a0b6109b4565b5b828203905092915050565b6000610a2282610785565b9150610a2d83610785565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610a6257610a616109b4565b5b82820190509291505056fea2646970667358221220c2a39c72e1159f474cd281822bb4f991a2ca9cf54aa4aa954a3f708aa9faafd964736f6c634300080a0033"));
    uint64_t amount = 999999999;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::TokenBalance(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::TokenTransfer(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::TokenCreateAddr(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::TokenTransferFrom(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::TokenApprove(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreateExTokenLib() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("610417610053600b82828239805160001a607314610046577f4e487b7100000000000000000000000000000000000000000000000000000000600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600436106100355760003560e01c806313311c201461003a575b600080fd5b81801561004657600080fd5b50610061600480360381019061005c91906102c1565b610063565b005b808460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156100ae57600080fd5b8360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054818560008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546101379190610357565b101561014257600080fd5b808460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825461019091906103ad565b92505081905550808460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546101e59190610357565b9250508190555050505050565b600080fd5b6000819050919050565b61020a816101f7565b811461021557600080fd5b50565b60008135905061022781610201565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006102588261022d565b9050919050565b6102688161024d565b811461027357600080fd5b50565b6000813590506102858161025f565b92915050565b6000819050919050565b61029e8161028b565b81146102a957600080fd5b50565b6000813590506102bb81610295565b92915050565b600080600080608085870312156102db576102da6101f2565b5b60006102e987828801610218565b94505060206102fa87828801610276565b935050604061030b87828801610276565b925050606061031c878288016102ac565b91505092959194509250565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006103628261028b565b915061036d8361028b565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156103a2576103a1610328565b5b828201905092915050565b60006103b88261028b565b91506103c38361028b565b9250828210156103d6576103d5610328565b5b82820390509291505056fea264697066735822122002b07aef69fd976c749be553c92ea320f0700aeb8d911c3d456a926278727c9164736f6c634300080a0033"));
    uint64_t amount = 999999999;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

std::string Command::CreateExToken() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("608060405233600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555034600080600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506109d7806100b96000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c8063095ea7b3146100675780630ecaea731461009757806323b872dd146100c757806367e404ce146100f757806370a0823114610115578063a9059cbb14610145575b600080fd5b610081600480360381019061007c91906106db565b610175565b60405161008e9190610736565b60405180910390f35b6100b160048036038101906100ac91906106db565b6102fb565b6040516100be9190610736565b60405180910390f35b6100e160048036038101906100dc9190610751565b61034a565b6040516100ee9190610736565b60405180910390f35b6100ff61051e565b60405161010c91906107c5565b60405180910390f35b61012f600480360381019061012a91906107e0565b610544565b60405161013c919061081c565b60405180910390f35b61015f600480360381019061015a91906106db565b61058c565b60405161016c9190610736565b60405180910390f35b600080600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414610235576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161022c9061086e565b60405180910390fd5b81600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055507f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9253384846040516102e99392919061089d565b60405180910390a16001905092915050565b6000816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506001905092915050565b600081600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156103d557600080fd5b81600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546104619190610903565b92505081905550600073afd200783f3a39a154b114b12898683c25c466cd6313311c2090918686866040518563ffffffff1660e01b81526004016104a8949392919061095c565b60006040518083038186803b1580156104c057600080fd5b505af41580156104d4573d6000803e3d6000fd5b505050507fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef84848460405161050b9392919061089d565b60405180910390a1600190509392505050565b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60008073afd200783f3a39a154b114b12898683c25c466cd6313311c2090913386866040518563ffffffff1660e01b81526004016105cd949392919061095c565b60006040518083038186803b1580156105e557600080fd5b505af41580156105f9573d6000803e3d6000fd5b505050507fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef3384846040516106309392919061089d565b60405180910390a16001905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061067282610647565b9050919050565b61068281610667565b811461068d57600080fd5b50565b60008135905061069f81610679565b92915050565b6000819050919050565b6106b8816106a5565b81146106c357600080fd5b50565b6000813590506106d5816106af565b92915050565b600080604083850312156106f2576106f1610642565b5b600061070085828601610690565b9250506020610711858286016106c6565b9150509250929050565b60008115159050919050565b6107308161071b565b82525050565b600060208201905061074b6000830184610727565b92915050565b60008060006060848603121561076a57610769610642565b5b600061077886828701610690565b935050602061078986828701610690565b925050604061079a868287016106c6565b9150509250925092565b60006107af82610647565b9050919050565b6107bf816107a4565b82525050565b60006020820190506107da60008301846107b6565b92915050565b6000602082840312156107f6576107f5610642565b5b600061080484828501610690565b91505092915050565b610816816106a5565b82525050565b6000602082019050610831600083018461080d565b92915050565b600082825260208201905092915050565b50565b6000610858600083610837565b915061086382610848565b600082019050919050565b600060208201905081810360008301526108878161084b565b9050919050565b61089781610667565b82525050565b60006060820190506108b2600083018661088e565b6108bf602083018561088e565b6108cc604083018461080d565b949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061090e826106a5565b9150610919836106a5565b92508282101561092c5761092b6108d4565b5b828203905092915050565b8082525050565b61094781610667565b82525050565b610956816106a5565b82525050565b60006080820190506109716000830187610937565b61097e602083018661093e565b61098b604083018561093e565b610998606083018461094d565b9594505050505056fea2646970667358221220237813d5b42c8320ec8b3acd7f9f3959766a3a0cf27c74e0b21295136fad488264736f6c634300080a0033"));
    uint64_t amount = 999999999;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, amount, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

std::string Command::CreateTestMath() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("60806040527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60005534801561003457600080fd5b5061043b806100446000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80636039b0bd146100465780637c3ffef214610076578063e5b5019a146100a6575b600080fd5b610060600480360381019061005b919061020c565b6100c4565b60405161006d9190610248565b60405180910390f35b610090600480360381019061008b9190610263565b6100d6565b60405161009d9190610248565b60405180910390f35b6100ae6100f3565b6040516100bb9190610248565b60405180910390f35b60006100cf826100f9565b9050919050565b60006100eb828461017390919063ffffffff16565b905092915050565b60005481565b6000600382111561016057819050600060016002846101189190610301565b6101229190610332565b90505b8181101561015a57809150600281828561013f9190610301565b6101499190610332565b6101539190610301565b9050610125565b5061016e565b6000821461016d57600190505b5b919050565b60008082846101829190610332565b9050838110156101c7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101be906103e5565b60405180910390fd5b8091505092915050565b600080fd5b6000819050919050565b6101e9816101d6565b81146101f457600080fd5b50565b600081359050610206816101e0565b92915050565b600060208284031215610222576102216101d1565b5b6000610230848285016101f7565b91505092915050565b610242816101d6565b82525050565b600060208201905061025d6000830184610239565b92915050565b6000806040838503121561027a576102796101d1565b5b6000610288858286016101f7565b9250506020610299858286016101f7565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061030c826101d6565b9150610317836101d6565b925082610327576103266102a3565b5b828204905092915050565b600061033d826101d6565b9150610348836101d6565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561037d5761037c6102d2565b5b828201905092915050565b600082825260208201905092915050565b7f75696e74206f766572666c6f7700000000000000000000000000000000000000600082015250565b60006103cf600d83610388565b91506103da82610399565b602082019050919050565b600060208201905081810360008301526103fe816103c2565b905091905056fea26469706673582212200d9200cfa6b60a9f652b52a28ee9da87e28c4953cc7bc864b92010018cb68d8564736f6c634300080a0033"));
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, 0, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::MathAdd(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("7c3ffef2000000000000000000000000000000000000000000000000000000001af63d920000000000000000000000000000000000000000000000000000000000285438");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

std::string Command::CreateExternMathLib() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("610447610053600b82828239805160001a607314610046577f4e487b7100000000000000000000000000000000000000000000000000000000600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600436106100565760003560e01c8063771602f71461005b578063a391c15b1461008b578063b67d77c5146100bb578063c8a4ac9c146100eb575b600080fd5b61007560048036038101906100709190610205565b61011b565b6040516100829190610254565b60405180910390f35b6100a560048036038101906100a09190610205565b610147565b6040516100b29190610254565b60405180910390f35b6100d560048036038101906100d09190610205565b610162565b6040516100e29190610254565b60405180910390f35b61010560048036038101906101009190610205565b610189565b6040516101129190610254565b60405180910390f35b600080828461012a919061029e565b90508381101561013d5761013c6102f4565b5b8091505092915050565b60008082846101569190610352565b90508091505092915050565b600082821115610175576101746102f4565b5b81836101819190610383565b905092915050565b600080828461019891906103b7565b905060008414806101b357508284826101b19190610352565b145b6101c0576101bf6102f4565b5b8091505092915050565b600080fd5b6000819050919050565b6101e2816101cf565b81146101ed57600080fd5b50565b6000813590506101ff816101d9565b92915050565b6000806040838503121561021c5761021b6101ca565b5b600061022a858286016101f0565b925050602061023b858286016101f0565b9150509250929050565b61024e816101cf565b82525050565b60006020820190506102696000830184610245565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006102a9826101cf565b91506102b4836101cf565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156102e9576102e861026f565b5b828201905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052600160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b600061035d826101cf565b9150610368836101cf565b92508261037857610377610323565b5b828204905092915050565b600061038e826101cf565b9150610399836101cf565b9250828210156103ac576103ab61026f565b5b828203905092915050565b60006103c2826101cf565b91506103cd836101cf565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04831182151516156104065761040561026f565b5b82820290509291505056fea26469706673582212201cfd3dc0f6b8abf382223740d69ebd65b69ae4ee9e549feb2b539bde0ba60d5d64736f6c634300080a0033"));
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, 0, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

std::string Command::CreateExternMath() {
    // create contract
    static const std::string purchase = common::Encode::HexDecode(std::string("608060405234801561001057600080fd5b50610423806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a9059cbb14610030575b600080fd5b61004a600480360381019061004591906102fd565b610060565b6040516100579190610358565b60405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020547397485911b11fca2c18b170c56a1a083e8f75ff1b63b67d77c59091846040518363ffffffff1660e01b81526004016100db929190610382565b602060405180830381865af41580156100f8573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061011c91906103c0565b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020547397485911b11fca2c18b170c56a1a083e8f75ff1b63771602f79091846040518363ffffffff1660e01b81526004016101d7929190610382565b602060405180830381865af41580156101f4573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061021891906103c0565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506001905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061029482610269565b9050919050565b6102a481610289565b81146102af57600080fd5b50565b6000813590506102c18161029b565b92915050565b6000819050919050565b6102da816102c7565b81146102e557600080fd5b50565b6000813590506102f7816102d1565b92915050565b6000806040838503121561031457610313610264565b5b6000610322858286016102b2565b9250506020610333858286016102e8565b9150509250929050565b60008115159050919050565b6103528161033d565b82525050565b600060208201905061036d6000830184610349565b92915050565b61037c816102c7565b82525050565b60006040820190506103976000830185610373565b6103a46020830184610373565b9392505050565b6000815190506103ba816102d1565b92915050565b6000602082840312156103d6576103d5610264565b5b60006103e4848285016103ab565b9150509291505056fea2646970667358221220f1fecb4e7ddec75231563d3b9514af89dcd02e86b7433994ca2194ce40d1160864736f6c634300080a0033"));
    uint64_t amount = 0;
    uint64_t gas_limit = 10000000;
    std::string contract_address;
    client::VpnClient::Instance()->CreateContract(purchase, 0, gas_limit, &contract_address);
    std::cout << "contract_address: " << common::Encode::HexEncode(contract_address) << std::endl;
    return contract_address;
}

void Command::ExtenMathAdd(const std::string& contract_addr) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a9059cbb000000000000000000000000544064949151817a1185e931ea43a71493f9f33c0000000000000000000000000000000000000000000000000000000000285438");
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

void Command::CallContract(const std::string& contract_addr, const std::string& params) {
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = params;
    uint64_t gas_usd = 1000000l + bft::kCallContractDefaultUseGas + bft::kTransferGas +
        (bft::kContractInputCode.size() + attrs[bft::kContractInputCode].size()) * bft::kKeyValueStorageEachBytes;
    std::string gid;
    client::VpnClient::Instance()->TransactionEx(
        contract_addr,
        0,
        gas_usd,
        common::kConsensusCallContract,
        attrs,
        gid);
}

#endif

}  // namespace init

}  // namespace tenon
