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
        std::cout << "balance: " << client::VpnClient::Instance()->GetBalance() << std::endl;
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
        for (int i = 0; i < count; ++i) {
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
        common::RemoteReachable(args[0], common::StringUtil::ToUint16(args[1]), &reachable);
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

#endif

}  // namespace init

}  // namespace tenon
