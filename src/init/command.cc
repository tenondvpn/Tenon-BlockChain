#include "stdafx.h"
#include "init/command.h"

#include <iostream>
#include <memory>
#include <thread>

#include "common/split.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/country_code.h"
#include "common/time_utils.h"
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

void Command::Run() {
    Help();
    while (!common::global_stop) {
        if (!show_cmd_) {
            std::this_thread::sleep_for(std::chrono::microseconds(200000ll));
            continue;
        }

        std::cout << std::endl << std::endl << "cmd > ";
        std::string cmdline;
        std::getline(std::cin, cmdline);
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
    AddCommand("cballot", [this](const std::vector<std::string>& args) {
        std::string contract_addr = CreateContractBallot();
        sleep(3);
        ChairmanSetVoters(contract_addr);
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
        tvm::Execution exec;
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
        exec.execute(code, input, "", "", "", 0, 0, 0, false, tenon_host, &res);
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
    // create contract
    static const std::string bytes_code = common::Encode::HexDecode(std::string("6080604052348015620000125760006000fd5b50604051620014a0380380620014a0833981810160405281019062000038919062000299565b5b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600160016000506000600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000506000016000508190909055506000600090505b8151811015620001ca576002600050604051806040016040528084848151811015156200014c577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101516000191681526020016000815260200150908060018154018082558091505060019003906000526020600020906002020160005b909190919091506000820151816000016000509060001916905560208201518160010160005090905550505b8080620001c19062000389565b915050620000f6565b505b506200046b566200046a565b6000620001ef620001e9846200030c565b620002e1565b90508083825260208201905082856020860282011115620002105760006000fd5b60005b8581101562000245578162000229888262000281565b8452602084019350602083019250505b60018101905062000213565b5050505b9392505050565b600082601f8301121515620002655760006000fd5b815162000277848260208601620001d8565b9150505b92915050565b60008151905062000292816200044c565b5b92915050565b600060208284031215620002ad5760006000fd5b600082015167ffffffffffffffff811115620002c95760006000fd5b620002d78482850162000250565b9150505b92915050565b6000620002ed62000301565b9050620002fb828262000352565b5b919050565b600060405190505b90565b600067ffffffffffffffff8211156200032a576200032962000409565b5b6020820290506020810190505b919050565b60008190505b919050565b60008190505b919050565b6200035d826200043a565b810181811067ffffffffffffffff821117156200037f576200037e62000409565b5b80604052505b5050565b6000620003968262000347565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415620003cc57620003cb620003d8565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b62000457816200033c565b81141515620004665760006000fd5b5b50565b5b611025806200047b6000396000f3fe60806040523480156100115760006000fd5b506004361061008d5760003560e01c8063609ff1bd1161005c578063609ff1bd1461011a5780639e7b8d6114610138578063a3ec138d14610154578063e2ba53f0146101875761008d565b80630121b93f14610093578063013cf08b146100af5780632e4176cf146100e05780635c19a95c146100fe5761008d565b60006000fd5b6100ad60048036038101906100a89190610afd565b6101a5565b005b6100c960048036038101906100c49190610afd565b610294565b6040516100d7929190610c54565b60405180910390f35b6100e86102d2565b6040516100f59190610c1c565b60405180910390f35b61011860048036038101906101139190610ad2565b6102f8565b005b6101226106f7565b60405161012f9190610d23565b60405180910390f35b610152600480360381019061014d9190610ad2565b6107f1565b005b61016e60048036038101906101699190610ad2565b6109cd565b60405161017e9493929190610d3f565b60405180910390f35b61018f610a33565b60405161019c9190610c38565b60405180910390f35b6000600160005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050905060018160010160006101000a81548160ff02191690831515021790555081816002016000508190909055508060000160005054600260005083815481101515610260577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600082828250546102869190610d97565b925050819090905550505b50565b600260005081815481106102a757600080fd5b906000526020600020906002020160005b915090508060000160005054908060010160005054905082565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff16151515610395576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161038c90610c7e565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610406576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103fd90610d02565b60405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160005060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561058857600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16915081503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610583576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161057a90610cc0565b60405180910390fd5b610407565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160005060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff16156106ca57816000016000505460026000508260020160005054815481101515610696577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600082828250546106bc9190610d97565b9250508190909055506106f1565b816000016000505481600001600082828250546106e79190610d97565b9250508190909055505b50505b50565b60006000600090506000600090505b6002600050805490508110156107eb5781600260005082815481101515610756577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b506001016000505411156107d7576002600050818154811015156107b4577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600050549150815080925082505b5b80806107e390610e45565b915050610706565b50505b90565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610883576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161087a90610c9f565b60405180910390fd5b600160005060008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160009054906101000a900460ff1615151561091b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161091290610ce1565b60405180910390fd5b6000600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050600001600050541415156109765760006000fd5b6001600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000506000016000508190909055505b50565b60016000506020528060005260406000206000915090508060000160005054908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160005054905084565b60006002600050610a486106f763ffffffff16565b815481101515610a81577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b5060000160005054905080505b9056610fee565b600081359050610ab581610fb8565b5b92915050565b600081359050610acb81610fd3565b5b92915050565b600060208284031215610ae55760006000fd5b6000610af384828501610aa6565b9150505b92915050565b600060208284031215610b105760006000fd5b6000610b1e84828501610abc565b9150505b92915050565b610b3181610dee565b82525b5050565b610b4181610e01565b82525b5050565b610b5181610e0e565b82525b5050565b6000610b65601283610d85565b9150610b7082610ec0565b6020820190505b919050565b6000610b89602883610d85565b9150610b9482610eea565b6040820190505b919050565b6000610bad601983610d85565b9150610bb882610f3a565b6020820190505b919050565b6000610bd1601883610d85565b9150610bdc82610f64565b6020820190505b919050565b6000610bf5601e83610d85565b9150610c0082610f8e565b6020820190505b919050565b610c1581610e3a565b82525b5050565b6000602082019050610c316000830184610b28565b5b92915050565b6000602082019050610c4d6000830184610b48565b5b92915050565b6000604082019050610c696000830185610b48565b610c766020830184610c0c565b5b9392505050565b60006020820190508181036000830152610c9781610b58565b90505b919050565b60006020820190508181036000830152610cb881610b7c565b90505b919050565b60006020820190508181036000830152610cd981610ba0565b90505b919050565b60006020820190508181036000830152610cfa81610bc4565b90505b919050565b60006020820190508181036000830152610d1b81610be8565b90505b919050565b6000602082019050610d386000830184610c0c565b5b92915050565b6000608082019050610d546000830187610c0c565b610d616020830186610b38565b610d6e6040830185610b28565b610d7b6060830184610c0c565b5b95945050505050565b60008282526020820190505b92915050565b6000610da282610e3a565b9150610dad83610e3a565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610de257610de1610e8f565b5b82820190505b92915050565b6000610df982610e19565b90505b919050565b600081151590505b919050565b60008190505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b6000610e5082610e3a565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415610e8357610e82610e8f565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f596f7520616c726561647920766f7465642e000000000000000000000000000060008201525b50565b7f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742060008201527f746f20766f74652e00000000000000000000000000000000000000000000000060208201525b50565b7f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000060008201525b50565b7f54686520766f74657220616c726561647920766f7465642e000000000000000060008201525b50565b7f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000060008201525b50565b610fc181610dee565b81141515610fcf5760006000fd5b5b50565b610fdc81610e3a565b81141515610fea5760006000fd5b5b50565bfea26469706673582212208a11da71baf451a53adabf2049084a2e24ceea212a4f9eae8a39afacdcc7453d64736f6c63430008030033") + "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8704348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8701348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8702");
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
    // call set voter
    for (auto iter = voters.begin(); iter != voters.end(); ++iter) {
        std::map<std::string, std::string> attrs;
        attrs[bft::kContractInputCode] = common::Encode::HexDecode("9e7b8d61000000000000000000000000" + *iter);
        uint64_t gas_usd = bft::kCallContractDefaultUseGas + + bft::kTransferGas + (
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

void Command::VoterSetDelegate(const std::string& contract_addr, const std::string& dest) {

}

void Command::Vote(const std::string& contract_addr) {

}


#endif

}  // namespace init

}  // namespace tenon
