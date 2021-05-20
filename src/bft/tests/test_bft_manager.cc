#include <gtest/gtest.h>

#include <iostream>
#include <chrono>

#define private public
#include "bft/bft_utils.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "transport/transport_utils.h"
#include "bft/bft_manager.h"
#include "block/account_manager.h"
#include "security/crypto_utils.h"
#include "election/elect_dht.h"
#include "network/dht_manager.h"
#include "network/universal_manager.h"
#include "bft/tests/test_transport.h"
#include "bft/tx_pool.h"
#include "bft/gid_manager.h"
#include "common/random.h"
#include "contract/contract_utils.h"
#include "security/secp256k1.h"
#include "tvm/execution.h"
#include "tvm/tvm_utils.h"
#include "tvm/tenon_host.h"

namespace tenon {

namespace bft {

namespace test {

static const std::string ballot_str = common::Encode::HexDecode("6080604052348015620000125760006000fd5b506040516200156338038062001563833981810160405281019062000038919062000299565b5b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600160016000506000600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000506000016000508190909055506000600090505b8151811015620001ca576002600050604051806040016040528084848151811015156200014c577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101516000191681526020016000815260200150908060018154018082558091505060019003906000526020600020906002020160005b909190919091506000820151816000016000509060001916905560208201518160010160005090905550505b8080620001c19062000389565b915050620000f6565b505b506200046b566200046a565b6000620001ef620001e9846200030c565b620002e1565b90508083825260208201905082856020860282011115620002105760006000fd5b60005b8581101562000245578162000229888262000281565b8452602084019350602083019250505b60018101905062000213565b5050505b9392505050565b600082601f8301121515620002655760006000fd5b815162000277848260208601620001d8565b9150505b92915050565b60008151905062000292816200044c565b5b92915050565b600060208284031215620002ad5760006000fd5b600082015167ffffffffffffffff811115620002c95760006000fd5b620002d78482850162000250565b9150505b92915050565b6000620002ed62000301565b9050620002fb828262000352565b5b919050565b600060405190505b90565b600067ffffffffffffffff8211156200032a576200032962000409565b5b6020820290506020810190505b919050565b60008190505b919050565b60008190505b919050565b6200035d826200043a565b810181811067ffffffffffffffff821117156200037f576200037e62000409565b5b80604052505b5050565b6000620003968262000347565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415620003cc57620003cb620003d8565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b62000457816200033c565b81141515620004665760006000fd5b5b50565b5b6110e8806200047b6000396000f3fe60806040523480156100115760006000fd5b506004361061008d5760003560e01c8063609ff1bd1161005c578063609ff1bd1461011a5780639e7b8d6114610138578063a3ec138d14610154578063e2ba53f0146101875761008d565b80630121b93f14610093578063013cf08b146100af5780632e4176cf146100e05780635c19a95c146100fe5761008d565b60006000fd5b6100ad60048036038101906100a89190610b51565b6101a5565b005b6100c960048036038101906100c49190610b51565b6102e8565b6040516100d7929190610ccc565b60405180910390f35b6100e8610326565b6040516100f59190610c94565b60405180910390f35b61011860048036038101906101139190610b26565b61034c565b005b61012261074b565b60405161012f9190610dbc565b60405180910390f35b610152600480360381019061014d9190610b26565b610845565b005b61016e60048036038101906101699190610b26565b610a21565b60405161017e9493929190610dd8565b60405180910390f35b61018f610a87565b60405161019c9190610cb0565b60405180910390f35b6000600160005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff16151515610242576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161023990610cf6565b60405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020160005081909090555080600001600050546002600050838154811015156102b4577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600082828250546102da9190610e30565b925050819090905550505b50565b600260005081815481106102fb57600080fd5b906000526020600020906002020160005b915090508060000160005054908060010160005054905082565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160005060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff161515156103e9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103e090610d17565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415151561045a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161045190610d9b565b60405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160005060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415156105dc57600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16915081503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141515156105d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105ce90610d59565b60405180910390fd5b61045b565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160005060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005090508060010160009054906101000a900460ff161561071e578160000160005054600260005082600201600050548154811015156106ea577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600082828250546107109190610e30565b925050819090905550610745565b8160000160005054816000016000828282505461073b9190610e30565b9250508190909055505b50505b50565b60006000600090506000600090505b60026000508054905081101561083f57816002600050828154811015156107aa577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b5060010160005054111561082b57600260005081815481101515610808577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b50600101600050549150815080925082505b5b808061083790610ede565b91505061075a565b50505b90565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156108d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108ce90610d38565b60405180910390fd5b600160005060008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060010160009054906101000a900460ff1615151561096f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161096690610d7a565b60405180910390fd5b6000600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050600001600050541415156109ca5760006000fd5b6001600160005060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000506000016000508190909055505b50565b60016000506020528060005260406000206000915090508060000160005054908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160005054905084565b60006002600050610a9c61074b63ffffffff16565b815481101515610ad5577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b906000526020600020906002020160005b5060000160005054905080505b90566110b1565b600081359050610b098161107b565b5b92915050565b600081359050610b1f81611096565b5b92915050565b600060208284031215610b395760006000fd5b6000610b4784828501610afa565b9150505b92915050565b600060208284031215610b645760006000fd5b6000610b7284828501610b10565b9150505b92915050565b610b8581610e87565b82525b5050565b610b9581610e9a565b82525b5050565b610ba581610ea7565b82525b5050565b6000610bb9600e83610e1e565b9150610bc482610f59565b6020820190505b919050565b6000610bdd601283610e1e565b9150610be882610f83565b6020820190505b919050565b6000610c01602883610e1e565b9150610c0c82610fad565b6040820190505b919050565b6000610c25601983610e1e565b9150610c3082610ffd565b6020820190505b919050565b6000610c49601883610e1e565b9150610c5482611027565b6020820190505b919050565b6000610c6d601e83610e1e565b9150610c7882611051565b6020820190505b919050565b610c8d81610ed3565b82525b5050565b6000602082019050610ca96000830184610b7c565b5b92915050565b6000602082019050610cc56000830184610b9c565b5b92915050565b6000604082019050610ce16000830185610b9c565b610cee6020830184610c84565b5b9392505050565b60006020820190508181036000830152610d0f81610bac565b90505b919050565b60006020820190508181036000830152610d3081610bd0565b90505b919050565b60006020820190508181036000830152610d5181610bf4565b90505b919050565b60006020820190508181036000830152610d7281610c18565b90505b919050565b60006020820190508181036000830152610d9381610c3c565b90505b919050565b60006020820190508181036000830152610db481610c60565b90505b919050565b6000602082019050610dd16000830184610c84565b5b92915050565b6000608082019050610ded6000830187610c84565b610dfa6020830186610b8c565b610e076040830185610b7c565b610e146060830184610c84565b5b95945050505050565b60008282526020820190505b92915050565b6000610e3b82610ed3565b9150610e4683610ed3565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610e7b57610e7a610f28565b5b82820190505b92915050565b6000610e9282610eb2565b90505b919050565b600081151590505b919050565b60008190505b919050565b600073ffffffffffffffffffffffffffffffffffffffff821690505b919050565b60008190505b919050565b6000610ee982610ed3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff821415610f1c57610f1b610f28565b5b6001820190505b919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b565b7f416c726561647920766f7465642e00000000000000000000000000000000000060008201525b50565b7f596f7520616c726561647920766f7465642e000000000000000000000000000060008201525b50565b7f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742060008201527f746f20766f74652e00000000000000000000000000000000000000000000000060208201525b50565b7f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000060008201525b50565b7f54686520766f74657220616c726561647920766f7465642e000000000000000060008201525b50565b7f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000060008201525b50565b61108481610e87565b811415156110925760006000fd5b5b50565b61109f81610ed3565b811415156110ad5760006000fd5b5b50565bfea26469706673582212206c27ddc47d392f4457bf022ed3c22834aeafe693b998b0e232e11ae8f73954f964736f6c6343000803003300000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8704348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8701348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8702");
static const std::string receive_pays = common::Encode::HexDecode("60806040523480156100115760006000fd5b50600436106100465760003560e01c806341c0e1b51461004c578063a90ae88714610056578063cfb519281461007257610046565b60006000fd5b6100546100a2565b005b610070600480360381019061006b9190610402565b61011a565b005b61008c600480360381019061008791906103be565b61029c565b604051610099919061048d565b60405180910390f35b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156100ff5760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff16ff5b565b6000601b905060007f3d584400dc77e383a2a2860d15fd181b1c36117d7b6c1e5d54e2f21d9491b66e60001b905060007f043a539fab3f2e42ba806da59b30e100077a7dba7439de3fce427eaa75dce5c460001b905060007ff559642966b18c5e58a82106d7cbb6dfaa449e1820dda477580b08bab68b93d560001b90506000600182868686604051600081526020016040526040516101bd94939291906104a9565b6020604051602081039080840390855afa1580156101e0573d600060003e3d6000fd5b505050602060405103519050600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415156102495760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc899081150290604051600060405180830381858888f19350505050158015610290573d600060003e3d6000fd5b5050505050505b505050565b600060008290506000815114156102ba57600060001b9150506102c3565b60208301519150505b9190505661063e565b60006102df6102da84610516565b6104ef565b9050828152602081018484840111156102f85760006000fd5b61030384828561059e565b505b9392505050565b600061031f61031a84610548565b6104ef565b9050828152602081018484840111156103385760006000fd5b61034384828561059e565b505b9392505050565b600082601f83011215156103605760006000fd5b81356103708482602086016102cc565b9150505b92915050565b600082601f830112151561038e5760006000fd5b813561039e84826020860161030c565b9150505b92915050565b6000813590506103b781610623565b5b92915050565b6000602082840312156103d15760006000fd5b600082013567ffffffffffffffff8111156103ec5760006000fd5b6103f88482850161037a565b9150505b92915050565b600060006000606084860312156104195760006000fd5b6000610427868287016103a8565b9350506020610438868287016103a8565b925050604084013567ffffffffffffffff8111156104565760006000fd5b6104628682870161034c565b9150505b9250925092565b6104768161057a565b82525b5050565b61048681610590565b82525b5050565b60006020820190506104a2600083018461046d565b5b92915050565b60006080820190506104be600083018761046d565b6104cb602083018661047d565b6104d8604083018561046d565b6104e5606083018461046d565b5b95945050505050565b60006104f961050b565b905061050582826105ae565b5b919050565b600060405190505b90565b600067ffffffffffffffff821115610531576105306105e0565b5b61053a82610611565b90506020810190505b919050565b600067ffffffffffffffff821115610563576105626105e0565b5b61056c82610611565b90506020810190505b919050565b60008190505b919050565b60008190505b919050565b600060ff821690505b919050565b828183376000838301525b505050565b6105b782610611565b810181811067ffffffffffffffff821117156105d6576105d56105e0565b5b80604052505b5050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b565b6000601f19601f83011690505b919050565b61062c81610585565b8114151561063a5760006000fd5b5b50565bfea26469706673582212205df1f066520c41781aa6e597f682192d353de3fdfe0f68038958a4170a2bf34264736f6c63430008030033");
class TestBftManager : public testing::Test {
public:
    static void WriteDefaultLogConf(
        const std::string& log_conf_path,
        const std::string& log_path) {
        FILE* file = NULL;
        file = fopen(log_conf_path.c_str(), "w");
        if (file == NULL) {
            return;
        }
        std::string log_str = ("# log4cpp.properties\n"
            "log4cpp.rootCategory = WARN\n"
            "log4cpp.category.sub1 = WARN, programLog\n"
            "log4cpp.appender.rootAppender = ConsoleAppender\n"
            "log4cpp.appender.rootAppender.layout = PatternLayout\n"
            "log4cpp.appender.rootAppender.layout.ConversionPattern = %d [%p] %m%n\n"
            "log4cpp.appender.programLog = RollingFileAppender\n"
            "log4cpp.appender.programLog.fileName = ") + log_path + "\n" +
            std::string("log4cpp.appender.programLog.maxFileSize = 1073741824\n"
                "log4cpp.appender.programLog.maxBackupIndex = 1\n"
                "log4cpp.appender.programLog.layout = PatternLayout\n"
                "log4cpp.appender.programLog.layout.ConversionPattern = %d [%p] %m%n\n");
        fwrite(log_str.c_str(), log_str.size(), 1, file);
        fclose(file);
    }

    static void SetUpTestCase() {
        tenon::bft::kBftStartDeltaTime = 1000;

        uint32_t* wait_bft_delay = const_cast<uint32_t*>(&bft::kBftStartDeltaTime);
        *wait_bft_delay = 1000;
        system("rm -rf ./core.* ./test_db");
        common::global_stop = true;
        db::Db::Instance()->Init("./test_db");
        std::string config_path_ = "./";
        std::string conf_path = config_path_ + "/tenon.conf";
        std::string log_conf_path = config_path_ + "/log4cpp.properties";
        std::string log_path = config_path_ + "/tenon.log";
        WriteDefaultLogConf(log_conf_path, log_path);
        log4cpp::PropertyConfigurator::configure(log_conf_path);

//         while (pool_index_map_.size() < common::kImmutablePoolSize) {
//             security::PrivateKey prikey;
//             security::PublicKey pubkey(prikey);
//             std::string pubkey_str;
//             ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
//             std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
//             auto pool_index = common::GetPoolIndex(address);
//             auto iter = pool_index_map_.find(pool_index);
//             if (iter != pool_index_map_.end()) {
//                 continue;
//             }
// 
//             std::string prikey_str;
//             ASSERT_EQ(prikey.Serialize(prikey_str), security::kPrivateKeySize);
//             pool_index_map_.insert(std::make_pair(pool_index, prikey_str));
//         }
// 
//         for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
//             std::cout << "pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(iter->second) << "\")));" << std::endl;
//         }

        pool_index_map_.insert(std::make_pair(0, common::Encode::HexDecode("b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6")));
        pool_index_map_.insert(std::make_pair(1, common::Encode::HexDecode("294ad6b66799796d822107b4dcb7a6a9c0c2fd743fddf93512ac921a0731d2de")));
        pool_index_map_.insert(std::make_pair(2, common::Encode::HexDecode("a834ef78741f8bc3f6263612c31c50a05ccdaf7add038849e709aee76c0e1151")));
        pool_index_map_.insert(std::make_pair(3, common::Encode::HexDecode("323b875d52948910330d81de19fc3d894232a333368819c2c12b6433151067ca")));
        pool_index_map_.insert(std::make_pair(4, common::Encode::HexDecode("0fedd74ffc1e65816f006eeeefa0497cb766eb9c1d238264cfd006f34152245d")));
        pool_index_map_.insert(std::make_pair(5, common::Encode::HexDecode("e5cd559f521e9d8fc6f07253b866ac79ca13c6ac02d50aff44509312e41a6f47")));
        pool_index_map_.insert(std::make_pair(6, common::Encode::HexDecode("d0a056e99a11564f75a6af4bb5cd06c1b373efdf6e64f04c42e64f94db2f80e4")));
        pool_index_map_.insert(std::make_pair(7, common::Encode::HexDecode("cbf17ab377d51731003f9ed093e02125e6c4ac78b5cc2d7f2bb0ca9deebdf6cd")));
        pool_index_map_.insert(std::make_pair(8, common::Encode::HexDecode("010cfd6f7f88f6be077b62c10c3f8f79277843a9e289eb5fc3fc65c8755f8f51")));
        pool_index_map_.insert(std::make_pair(9, common::Encode::HexDecode("f5ba6ea0edfb33f9f1e44e434872fbf9e6f403c88d5d37ddf57235d573fd4c7a")));
        pool_index_map_.insert(std::make_pair(10, common::Encode::HexDecode("c627c5ac57e89516c677f6731c15b345087db9ff552a20fb40cffc44234aa8ce")));
        pool_index_map_.insert(std::make_pair(11, common::Encode::HexDecode("81db11fd404ae99c333a50c3140a29e4fc267e0519276cf63b89efe7ba7a1e40")));
        pool_index_map_.insert(std::make_pair(12, common::Encode::HexDecode("5640c58362fc5858474bb9f686d70cd685e3c2fb26f033dca2c7fc4b64679500")));
        pool_index_map_.insert(std::make_pair(13, common::Encode::HexDecode("8379d77981871f5439b98f811ae9c22670ae2e7d872b11ed20a576019be4a270")));
        pool_index_map_.insert(std::make_pair(14, common::Encode::HexDecode("f55797602d3b5955f3f9d99ffb1b8ed39c7a345472127b6db4dc8ef0b8893928")));
        pool_index_map_.insert(std::make_pair(15, common::Encode::HexDecode("ee303c6dfb067fc8dd0c19e4aeaf7901cb1393e123bfca57cfd43e9f30462873")));
        pool_index_map_.insert(std::make_pair(16, common::Encode::HexDecode("dd672dd8d64c56e22ad2696708a56d36c20cfdce546a0e8291fd7b721ca83dfe")));
        pool_index_map_.insert(std::make_pair(17, common::Encode::HexDecode("db759a1db3cb82d9a8668c569516a2e725265d93449bdfffcaefa4b25b5e726f")));
        pool_index_map_.insert(std::make_pair(18, common::Encode::HexDecode("08d717b745a8593f69beccbbc1ac05584bde045c4c5f57c14ee3140161f9543d")));
        pool_index_map_.insert(std::make_pair(19, common::Encode::HexDecode("713acc06c1a292f8902975f0538f4b7f50388b303154d6a95ead7d91386e5c68")));
        pool_index_map_.insert(std::make_pair(20, common::Encode::HexDecode("0a25fcd049cf67b52e6a44bad7b98b3f02a6ccc572190649691e141b6bc37aff")));
        pool_index_map_.insert(std::make_pair(21, common::Encode::HexDecode("a0b22507aff97e5e47a051436b3acf749f2cd052e7d4d2017281e2a1f873a653")));
        pool_index_map_.insert(std::make_pair(22, common::Encode::HexDecode("520005390b419a60a53fb62405644507f0d6c3e2862dd8acd5662c8d42088585")));
        pool_index_map_.insert(std::make_pair(23, common::Encode::HexDecode("e2690365aa06865f11e4a18e37b04c7839175276dc11e86b7da0a478387c2842")));
        pool_index_map_.insert(std::make_pair(24, common::Encode::HexDecode("eb592e3fb7838de0a33effa3462dab0d52376c911bedaa68d513548d5c367bad")));
        pool_index_map_.insert(std::make_pair(25, common::Encode::HexDecode("c61d917451c041c6d45c62f2306734bd8259aa4d33fb16c6b4d39db6cec02ab6")));
        pool_index_map_.insert(std::make_pair(26, common::Encode::HexDecode("6da5f6787dbb88eb83b08d52e9514f9688c09af89bb5aab9f1a8b49e70382954")));
        pool_index_map_.insert(std::make_pair(27, common::Encode::HexDecode("b5a93a83f93113b677a18713015dd349a6efec561ae2f101ea8a538de1323765")));
        pool_index_map_.insert(std::make_pair(28, common::Encode::HexDecode("b998de215ae5f7c23fcd7b8e55974a466c6b5e29019d45a95a5035c2512f7fff")));
        pool_index_map_.insert(std::make_pair(29, common::Encode::HexDecode("d4dab7c1c2acd53e03a9601a2ff65a17d7038da41ae836d4e27b8c5981cedf0a")));
        pool_index_map_.insert(std::make_pair(30, common::Encode::HexDecode("0392fefaaf0a5ae974f411c73d1e4d2d065080c77b267baf89142de958745f08")));
        pool_index_map_.insert(std::make_pair(31, common::Encode::HexDecode("ff605ad605d73204a97492be36a9e7ccd1c9532f330b906feb16f55b3cdbd261")));
        pool_index_map_.insert(std::make_pair(32, common::Encode::HexDecode("a7eae03fb5903ed80c1376ff173bcc884d607c7fe780dd726a3993f1015f1028")));
        pool_index_map_.insert(std::make_pair(33, common::Encode::HexDecode("76482bf9e7d69d1e4f460731c79993a8bee579c51a225127fb5044f2c923ca5f")));
        pool_index_map_.insert(std::make_pair(34, common::Encode::HexDecode("2743547f69cfca2692ba7b0e0e3396a96b3330235e544e27abf96b57344daaf1")));
        pool_index_map_.insert(std::make_pair(35, common::Encode::HexDecode("a70604f5432da3deaf1c89439f0671c684a03a168ee96bdf11b93eb47343752b")));
        pool_index_map_.insert(std::make_pair(36, common::Encode::HexDecode("6984a610cc6b55817b373f4602c56db07bfc243afa36d7424685348c4fbcdc45")));
        pool_index_map_.insert(std::make_pair(37, common::Encode::HexDecode("68a4580ad70fbc56c6d0f1b410f1c2ba8b2826306a57d3bcd3e6763e0ba29e76")));
        pool_index_map_.insert(std::make_pair(38, common::Encode::HexDecode("90dc94f6820d17c6c1027451bd141912dd3a4d41f683b99f8676b2f62925aeb7")));
        pool_index_map_.insert(std::make_pair(39, common::Encode::HexDecode("93ade5f5b072cb712cfee8cba8917bc3067f5bfd74e8b781f2f5171eb9c6fca9")));
        pool_index_map_.insert(std::make_pair(40, common::Encode::HexDecode("8e4171b50da6d0b8ede12d9506499748579524767ed8e96960ddcb22e87b3a96")));
        pool_index_map_.insert(std::make_pair(41, common::Encode::HexDecode("3fe4f6b512b84469b15f91cc68f817e8924f3d698361124f2915bf992524cbcb")));
        pool_index_map_.insert(std::make_pair(42, common::Encode::HexDecode("9c0c35a98b8d5ff63000ee875fbf91d0828ccb95bd9a5fd2e8c929f1900289b2")));
        pool_index_map_.insert(std::make_pair(43, common::Encode::HexDecode("f87c3e4b3ea584b1f944b82dd4a6904b54cb46fcd3f8cd7baa0c14843f7ea7bf")));
        pool_index_map_.insert(std::make_pair(44, common::Encode::HexDecode("ddac94b039a6ae659ad8e51ad43e4b720d1238f5cd01cae4d2639e2177744725")));
        pool_index_map_.insert(std::make_pair(45, common::Encode::HexDecode("e5cb18fe22135f6f8d96c3271f6570cc59462292a25c3b792418377a37edc115")));
        pool_index_map_.insert(std::make_pair(46, common::Encode::HexDecode("2bbe593aa80c7dfe587530446e7abc03b1bf12dfb2606ea74b47fb529cab92e5")));
        pool_index_map_.insert(std::make_pair(47, common::Encode::HexDecode("6dc3f90ab471e37382b712aa1ff445d043ce801f6161b7b0e362616e05febd07")));
        pool_index_map_.insert(std::make_pair(48, common::Encode::HexDecode("5df6d4ef4b4308f7bdd8c99444714ec52217c2a568a64716e6e109e612b8c598")));
        pool_index_map_.insert(std::make_pair(49, common::Encode::HexDecode("a5056891b513f2df869d00b90019dfdd74a51b10dd15afdc2c879c2351bead65")));
        pool_index_map_.insert(std::make_pair(50, common::Encode::HexDecode("225abeb86f7dbc2dc02bdfc826513f6277510c856b8ca5b21535655ffccfc5e5")));
        pool_index_map_.insert(std::make_pair(51, common::Encode::HexDecode("f1d181e02753f0a8da022095d4d74473227e939f6b50ce600b40801f0d5766b4")));
        pool_index_map_.insert(std::make_pair(52, common::Encode::HexDecode("6e0c1236c2dbdccc6d26d4399c7fca88f9265165e1bbd5568e168eaa26760caa")));
        pool_index_map_.insert(std::make_pair(53, common::Encode::HexDecode("b818aeefa8253549f42e7105dd946faba81ccf60c1ace50734825e925f6f348c")));
        pool_index_map_.insert(std::make_pair(54, common::Encode::HexDecode("a0931639f512a991c46055808752b65b51fa003673503356e10046ac8e57e328")));
        pool_index_map_.insert(std::make_pair(55, common::Encode::HexDecode("f484c02dabc8a0ec3d0e1b75cb1f7cd0e81d17ac29712a5a18b6a689fd1afb93")));
        pool_index_map_.insert(std::make_pair(56, common::Encode::HexDecode("624c5422ec2776f892d56718258c50f29b577135b259c727b29bfb6dafcea7e5")));
        pool_index_map_.insert(std::make_pair(57, common::Encode::HexDecode("4a8184505b56d11effb9cc4a8edce9abef35ce0482a5e2ba43dcf79d57a9f4a0")));
        pool_index_map_.insert(std::make_pair(58, common::Encode::HexDecode("cf3555535837b78d8a944b90a415b8d8492aba1289ec962fb4b3a22e78e2e135")));
        pool_index_map_.insert(std::make_pair(59, common::Encode::HexDecode("c92503f9647df7340500b323233036c30d96b6f01747cdf4eb996f5d7358c518")));
        pool_index_map_.insert(std::make_pair(60, common::Encode::HexDecode("a86857de21eb88f0e3b8a164ddf8b6cc570c509efff21143d3ee282a920c769d")));
        pool_index_map_.insert(std::make_pair(61, common::Encode::HexDecode("78dcd96f41e69dbc7bfdd98c95c951686908ad70896c34fe66543669b4b1d80f")));
        pool_index_map_.insert(std::make_pair(62, common::Encode::HexDecode("267bc076e3860457da661168ca4758141f048af1bcc449a91fd6dea8673e30db")));
        pool_index_map_.insert(std::make_pair(63, common::Encode::HexDecode("9c59e2c30ad1a10336e2e55f4186a8856f7107f84df3f8f89a13dda311da9568")));

        InitEnv();
    }

    static void AddGenisisBlock(uint32_t type) {
        uint64_t genesis_account_balance = 21000000000llu * common::kTenonMiniTransportUnit / pool_index_map_.size();
        uint64_t all_balance = 0llu;
        for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
            bft::protobuf::Block tenon_block;
            auto tx_list = tenon_block.mutable_tx_list();
            security::PrivateKey prikey(iter->second);
            security::PublicKey pubkey(prikey);
            std::string pubkey_str;
            ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
            std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
            auto tx_info = tx_list->Add();
            tx_info->set_version(common::kTransactionVersion);
            tx_info->set_gid(common::CreateGID(""));
            tx_info->set_from(address);
            tx_info->set_from_pubkey(pubkey_str);
            tx_info->set_from_sign("");
            tx_info->set_to("");
            tx_info->set_amount(genesis_account_balance);
            tx_info->set_balance(genesis_account_balance);
            tx_info->set_gas_limit(0);
            tx_info->set_type(type);
            tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
            tenon_block.set_prehash("");
            tenon_block.set_version(common::kTransactionVersion);
            tenon_block.set_elect_ver(0);
            tenon_block.set_agg_pubkey("");
            tenon_block.set_agg_sign_challenge("");
            tenon_block.set_agg_sign_response("");
            tenon_block.set_pool_index(iter->first);
            tenon_block.set_height(0);
            tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
            tenon_block.set_hash(GetBlockHash(tenon_block));
            ASSERT_EQ(BftManager::Instance()->AddGenisisBlock(tenon_block), kBftSuccess);
            std::string pool_hash;
            uint64_t pool_height = 0;
            int res = block::AccountManager::Instance()->GetBlockInfo(
                iter->first,
                &pool_height,
                &pool_hash);
            ASSERT_EQ(res, block::kBlockSuccess);
            ASSERT_EQ(pool_height, 0);
            ASSERT_EQ(pool_hash, GetBlockHash(tenon_block));
            auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
            ASSERT_FALSE(account_ptr == nullptr);
            uint64_t balance = 0;
            ASSERT_EQ(account_ptr->GetBalance(&balance), block::kBlockSuccess);
            ASSERT_EQ(balance, genesis_account_balance);
            all_balance += balance;
        }

        ASSERT_EQ(all_balance, 21000000000llu * common::kTenonMiniTransportUnit);
    }

    void CreateNewTransaction(
            const std::string& from_prikey,
            const std::string& to_prikey,
            uint64_t amount,
            uint64_t gas_limit,
            uint32_t tx_type,
            bool just_to_id,
            std::map<std::string, std::string>& attrs,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key("");
        uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityHighest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBftMessage);
        msg.set_client(false);
        msg.set_hop_count(0);
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
        bft::protobuf::BftMessage bft_msg;
        bft_msg.set_gid(common::CreateGID(""));
        bft_msg.set_rand(0);
        bft_msg.set_bft_step(bft::kBftInit);
        bft_msg.set_leader(false);
        bft_msg.set_net_id(des_net_id);
        security::PrivateKey from_private_key(from_prikey);
        security::PublicKey from_pubkey(from_private_key);
        std::string from_pubkey_str;
        ASSERT_EQ(from_pubkey.Serialize(from_pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(from_pubkey_str);
        if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
            uint32_t from_net_id = 0;
            ASSERT_EQ(block::AccountManager::Instance()->GetAddressConsensusNetworkId(
                id,
                &from_net_id), block::kBlockSuccess);
            ASSERT_EQ(from_net_id, common::GlobalInfo::Instance()->network_id());
        }
        
        bft_msg.set_node_id(id);
        bft_msg.set_pubkey(from_pubkey_str);
        bft::protobuf::TxBft tx_bft;
        auto new_tx = tx_bft.mutable_new_tx();
        new_tx->set_gid(common::CreateGID(from_pubkey_str));
        new_tx->set_from(id);
        new_tx->set_from_pubkey(from_pubkey_str);
        if (!to_prikey.empty() && !just_to_id) {
            security::PrivateKey to_private_key(to_prikey);
            security::PublicKey to_pubkey(to_private_key);
            std::string to_pubkey_str;
            ASSERT_EQ(to_pubkey.Serialize(to_pubkey_str, false), security::kPublicKeyUncompressSize);
            std::string to_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(to_pubkey_str);
            new_tx->set_to(to_id);
        }

        if (just_to_id) {
            new_tx->set_to(to_prikey);
        }

        if (tx_type == common::kConsensusCreateContract) {
            ASSERT_TRUE(attrs.find(bft::kContractBytesCode) != attrs.end());
            std::string contract_addres = security::Secp256k1::Instance()->GetContractAddress(
                id,
                new_tx->gid(),
                attrs[bft::kContractBytesCode]);
            new_tx->set_to(contract_addres);
        }

        new_tx->set_amount(amount);
        new_tx->set_gas_limit(gas_limit);
        new_tx->set_type(tx_type);
        for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
            auto attr = new_tx->add_attr();
            attr->set_key(iter->first);
            attr->set_value(iter->second);
        }

        auto hash128 = GetTxMessageHash(*new_tx);
        auto tx_data = tx_bft.SerializeAsString();
        bft_msg.set_data(tx_data);
        security::Signature sign;
        ASSERT_TRUE(security::Schnorr::Instance()->Sign(
            hash128,
            from_private_key,
            from_pubkey,
            sign));
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        msg.set_data(bft_msg.SerializeAsString());
    }

    void CreateTransaction(
            uint32_t bft_step,
            const std::string& from_prikey,
            const std::string& to_prikey,
            bool to_add,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key("");
        uint32_t des_net_id = network::kConsensusShardBeginNetworkId;
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityHighest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBftMessage);
        msg.set_client(false);
        msg.set_hop_count(0);
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
        bft::protobuf::BftMessage bft_msg;
        bft_msg.set_gid(common::CreateGID(""));
        bft_msg.set_rand(0);
        bft_msg.set_bft_step(bft_step);
        bft_msg.set_leader(false);
        bft_msg.set_net_id(des_net_id);
        security::PrivateKey from_private_key(from_prikey);
        security::PublicKey from_pubkey(from_private_key);
        std::string from_pubkey_str;
        ASSERT_EQ(from_pubkey.Serialize(from_pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(from_pubkey_str);

        if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
            uint32_t from_net_id = 0;
            ASSERT_EQ(block::AccountManager::Instance()->GetAddressConsensusNetworkId(
                id,
                &from_net_id), block::kBlockSuccess);
            ASSERT_EQ(from_net_id, common::GlobalInfo::Instance()->network_id());
        }

        bft_msg.set_node_id(id);
        bft_msg.set_pubkey(from_pubkey_str);
        bft::protobuf::TxBft tx_bft;
        auto to_tx = tx_bft.mutable_to_tx();
        auto block = to_tx->mutable_block();
        auto tx_info = block->mutable_tx_list()->Add();
        tx_info->set_gid(common::CreateGID(from_pubkey_str));
        tx_info->set_from(id);
        tx_info->set_from_pubkey(from_pubkey_str);
        tx_info->set_to_add(to_add);
        tx_info->set_status(kBftSuccess);
        tx_info->set_type(common::kConsensusTransaction);
        security::PrivateKey to_private_key(to_prikey);
        security::PublicKey to_pubkey(to_private_key);
        std::string to_pubkey_str;
        ASSERT_EQ(to_pubkey.Serialize(to_pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string to_id = security::Secp256k1::Instance()->ToAddressWithPublicKey(to_pubkey_str);
        tx_info->set_to(to_id);
        tx_info->set_amount(10llu * common::kTenonMiniTransportUnit);
        tx_info->set_gas_limit(1000000);

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint32_t pool_index = common::GetPoolIndex(id);
        int res = block::AccountManager::Instance()->GetBlockInfo(
            pool_index,
            &pool_height,
            &pool_hash);
        if (res != block::kBlockSuccess) {
            assert(false);
            return;
        }

        block->set_prehash(pool_hash);
        block->set_version(common::kTransactionVersion);
        block->set_elect_ver(common::GlobalInfo::Instance()->now_elect_version());
        block->set_network_id(common::GlobalInfo::Instance()->network_id());
        block->set_consistency_random(crand::ConsistencyRandom::Instance()->Random());
        block->set_height(pool_height + 1);
        block->set_timestamp(common::TimeStampMsec());
        block->set_hash(GetBlockHash(*block));

        auto tx_data = tx_bft.SerializeAsString();
        bft_msg.set_data(tx_data);
        security::Signature sign;
        ASSERT_TRUE(security::Schnorr::Instance()->Sign(
            block->hash(),
            from_private_key,
            from_pubkey,
            sign));
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        msg.set_data(bft_msg.SerializeAsString());
    }

    static void CreateElectionBlock(uint32_t network_id, std::vector<std::string>& pri_vec) {
        std::map<uint32_t, bft::MembersPtr> in_members;
        std::map<uint32_t, bft::MembersPtr> out_members;
        std::map<uint32_t, bft::NodeIndexMapPtr> in_index_members;
        std::map<uint32_t, uint32_t> begin_index_map_;
        for (uint32_t i = 0; i < pri_vec.size(); ++i) {
            auto net_id = network_id;
            auto iter = in_members.find(net_id);
            if (iter == in_members.end()) {
                in_members[net_id] = std::make_shared<bft::Members>();
                in_index_members[net_id] = std::make_shared<
                    std::unordered_map<std::string, uint32_t>>();
                begin_index_map_[net_id] = 0;
            }

            security::PrivateKey prikey(pri_vec[i]);
            security::PublicKey pubkey(prikey);
            std::string pubkey_str;
            ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
            std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
            security::CommitSecret secret;
            in_members[net_id]->push_back(std::make_shared<bft::BftMember>(
                net_id, id, pubkey_str, begin_index_map_[net_id]));
            in_index_members[net_id]->insert(std::make_pair(id, begin_index_map_[net_id]));
            ++begin_index_map_[net_id];
        }

        for (auto iter = in_members.begin(); iter != in_members.end(); ++iter) {
            auto index_map_iter = in_index_members.find(iter->first);
            ASSERT_TRUE(index_map_iter != in_index_members.end());
            bft::BftManager::Instance()->NetworkMemberChange(
                iter->first,
                iter->second,
                index_map_iter->second);
            ASSERT_TRUE(bft::MemberManager::Instance()->network_members_[iter->first] != nullptr);
            ASSERT_TRUE(bft::MemberManager::Instance()->node_index_map_[iter->first] != nullptr);
        }
    }

    static void JoinNetwork(uint32_t network_id) {
        network::DhtManager::Instance()->UnRegisterDht(network_id);
        network::UniversalManager::Instance()->UnRegisterUniversal(network_id);
        dht::DhtKeyManager dht_key(
            network_id,
            common::GlobalInfo::Instance()->country(),
            common::GlobalInfo::Instance()->id());
        dht::NodePtr local_node = std::make_shared<dht::Node>(
            common::GlobalInfo::Instance()->id(),
            dht_key.StrKey(),
            dht::kNatTypeFullcone,
            false,
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port(),
            security::Schnorr::Instance()->str_pubkey(),
            common::GlobalInfo::Instance()->node_tag());
        local_node->first_node = true;
        transport::TransportPtr transport;
        auto dht = std::make_shared<elect::ElectDht>(transport, local_node);
        dht->Init();
        auto base_dht = std::dynamic_pointer_cast<dht::BaseDht>(dht);
        network::DhtManager::Instance()->RegisterDht(network_id, base_dht);
        network::UniversalManager::Instance()->RegisterUniversal(network_id, base_dht);
    }

    static void InitEnv() {
        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kRootCongressNetworkId);
        {
            // root shard
            std::vector<std::string> pri_vec;
            pri_vec.push_back(common::Encode::HexDecode("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e"));
            pri_vec.push_back(common::Encode::HexDecode("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e"));
            pri_vec.push_back(common::Encode::HexDecode("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e"));
            CreateElectionBlock(network::kRootCongressNetworkId, pri_vec);
            ASSERT_TRUE(bft::MemberManager::Instance()->IsLeader(
                network::kRootCongressNetworkId,
                common::GlobalInfo::Instance()->id(),
                crand::ConsistencyRandom::Instance()->Random()));
        }

        {
            // consensus shard
            std::vector<std::string> pri_vec;
            pri_vec.push_back(common::Encode::HexDecode("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e"));
            pri_vec.push_back(common::Encode::HexDecode("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e"));
            pri_vec.push_back(common::Encode::HexDecode("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e"));
            CreateElectionBlock(network::kConsensusShardBeginNetworkId, pri_vec);
        }

        auto transport_ptr = std::dynamic_pointer_cast<transport::Transport>(
            std::make_shared<transport::TestTransport>());
        transport::MultiThreadHandler::Instance()->Init(transport_ptr, transport_ptr);
        AddGenisisBlock(common::kConsensusCreateGenesisAcount);
    }

    static void SetGloableInfo(const std::string& private_key, uint32_t network_id) {
        security::PrivateKey prikey(common::Encode::HexDecode(private_key));
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        security::Schnorr::Instance()->set_prikey(std::make_shared<security::PrivateKey>(prikey));
        common::GlobalInfo::Instance()->set_id(id);
        common::GlobalInfo::Instance()->set_consensus_shard_count(1);
        common::GlobalInfo::Instance()->set_network_id(network_id);
        JoinNetwork(network::kRootCongressNetworkId);
        JoinNetwork(network::kUniversalNetworkId);
        JoinNetwork(network::kConsensusShardBeginNetworkId);
    }

    static std::string GetAccountIdByPrikey(const std::string& private_key) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        EXPECT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        return id;
    }

    static void RemoveAccountId(const std::string& id) {
        auto iter = block::AccountManager::Instance()->acc_map_.find(id);
        if (iter != block::AccountManager::Instance()->acc_map_.end()) {
            block::AccountManager::Instance()->acc_map_.erase(iter);
        }

        auto set_iter = block::DbAccountInfo::account_id_set_.find(id);
        if (set_iter != block::DbAccountInfo::account_id_set_.end()) {
            block::DbAccountInfo::account_id_set_.erase(set_iter);
        }

        std::string key = db::kGlobalDickKeyAccountIdExists + "_" + id;
        db::Db::Instance()->Delete(key);
    }

    static void AddConsensusBlocks() {

    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
        broad_param->set_layer_left(0);
        broad_param->set_layer_right(((std::numeric_limits<uint64_t>::max))());
        broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
        broad_param->set_stop_times(kBftBroadcastStopTimes);
        broad_param->set_hop_limit(kBftHopLimit);
        broad_param->set_hop_to_layer(kBftHopToLayer);
        broad_param->set_neighbor_count(kBftNeighborCount);
    }

    void AddNewTxToTxPool(const bft::protobuf::TxInfo& tx_info) {
        auto tx_ptr = std::make_shared<TxItem>(tx_info);
        GidManager::Instance()->NewGidTxValid(tx_ptr->tx.gid(), tx_ptr);
    }

    void ResetBftSecret(const std::string& bft_gid, uint32_t net_id, const std::string& id) {
        uint32_t member_index = MemberManager::Instance()->GetMemberIndex(net_id, id);
        auto mem_ptr = MemberManager::Instance()->GetMember(net_id, member_index);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid]->secret_ = mem_ptr->secret;
    }

    void Transfer(
            const std::string& from_prikey,
            const std::string& to_prikey,
            uint64_t amount,
            uint64_t gas_limit,
            uint32_t tx_type,
            bool just_to_id,
            std::map<std::string, std::string>& attrs,
            transport::protobuf::Header* broadcast_msg) {
        transport::protobuf::Header msg;
        CreateNewTransaction(from_prikey, to_prikey, amount, gas_limit, tx_type, just_to_id, attrs, msg);
        bft::protobuf::BftMessage bft_msg;
        bft_msg.ParseFromString(msg.data());
        bft::protobuf::TxBft tx_bft;
        EXPECT_TRUE(tx_bft.ParseFromString(bft_msg.data()));
        
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(msg);
        usleep(bft::kBftStartDeltaTime);
        ASSERT_EQ(bft::BftManager::Instance()->StartBft(""), kBftSuccess);

        auto bft_gid = common::GlobalInfo::Instance()->gid_hash_ +
            std::to_string(common::GlobalInfo::Instance()->gid_idx_ - 1);
        auto iter = bft::BftManager::Instance()->bft_hash_map_.find(bft_gid);
        ASSERT_TRUE(iter != bft::BftManager::Instance()->bft_hash_map_.end());
        auto leader_prepare_msg = bft::BftManager::Instance()->leader_prepare_msg_;
        auto leader_prepare_msg2 = bft::BftManager::Instance()->leader_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(leader_prepare_msg.data()));
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(leader_prepare_msg);
        auto backup1_prepare_msg = bft::BftManager::Instance()->backup_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup1_prepare_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(leader_prepare_msg2);
        auto backup2_prepare_msg = bft::BftManager::Instance()->backup_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup2_prepare_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        // precommit
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(backup1_prepare_msg);
        bft::BftManager::Instance()->HandleMessage(backup2_prepare_msg);

        auto leader_precommit_msg = bft::BftManager::Instance()->leader_precommit_msg_;
        auto leader_precommit_msg2 = bft::BftManager::Instance()->leader_precommit_msg_;
        ASSERT_TRUE(leader_precommit_msg.has_data());
        ASSERT_TRUE(leader_precommit_msg2.has_data());

        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(leader_precommit_msg.data()));
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kConsensusShardBeginNetworkId);
        ResetBftSecret(bft_gid, network::kConsensusShardBeginNetworkId, common::GlobalInfo::Instance()->id());
        bft::BftManager::Instance()->HandleMessage(leader_precommit_msg);
        auto backup1_precommit_msg = bft::BftManager::Instance()->backup_precommit_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup1_precommit_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kConsensusShardBeginNetworkId);
        ResetBftSecret(bft_gid, network::kConsensusShardBeginNetworkId, common::GlobalInfo::Instance()->id());
        bft::BftManager::Instance()->HandleMessage(leader_precommit_msg2);
        auto backup2_precommit_msg = bft::BftManager::Instance()->backup_precommit_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup2_precommit_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        // commit
        uint32_t member_index = MemberManager::Instance()->GetMemberIndex(network::kConsensusShardBeginNetworkId, common::GlobalInfo::Instance()->id());
        auto mem_ptr = MemberManager::Instance()->GetMember(network::kConsensusShardBeginNetworkId, member_index);
        auto bft_ptr = bft::BftManager::Instance()->bft_hash_map_[bft_gid];

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(backup1_precommit_msg);
        bft::BftManager::Instance()->HandleMessage(backup2_precommit_msg);
        auto leader_commit_msg = bft::BftManager::Instance()->leader_commit_msg_;
        auto leader_commit_msg2 = bft::BftManager::Instance()->leader_commit_msg_;
        ASSERT_TRUE(leader_commit_msg.has_data());
        ASSERT_TRUE(leader_commit_msg2.has_data());
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(leader_commit_msg.data()));
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        *broadcast_msg = bft::BftManager::Instance()->to_leader_broadcast_msg_;
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid] = bft_ptr;
        bft::BftManager::Instance()->HandleMessage(leader_commit_msg);
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid] = bft_ptr;
        bft::BftManager::Instance()->HandleMessage(leader_commit_msg2);
    }

    void CreateNewAccount(
            const std::string& from_prikey,
            const std::string& to_prikey,
            transport::protobuf::Header& msg,
            transport::protobuf::Header* broadcast_msg) {
        bft::protobuf::BftMessage bft_msg;
        bft_msg.ParseFromString(msg.data());
        bft::protobuf::TxBft tx_bft;
        EXPECT_TRUE(tx_bft.ParseFromString(bft_msg.data()));

        // prepare
        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->HandleMessage(msg);
        usleep(bft::kBftStartDeltaTime);
        EXPECT_EQ(bft::BftManager::Instance()->StartBft(""), kBftSuccess);

        auto bft_gid = common::GlobalInfo::Instance()->gid_hash_ +
            std::to_string(common::GlobalInfo::Instance()->gid_idx_ - 1);
        auto iter = bft::BftManager::Instance()->bft_hash_map_.find(bft_gid);
        ASSERT_TRUE(iter != bft::BftManager::Instance()->bft_hash_map_.end());

        auto leader_prepare_msg = bft::BftManager::Instance()->leader_prepare_msg_;
        auto leader_prepare_msg2 = bft::BftManager::Instance()->leader_prepare_msg_;
        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->HandleMessage(leader_prepare_msg);
        AddNewTxToTxPool(tx_bft.to_tx().block().tx_list(0));
        auto backup1_prepare_msg = bft::BftManager::Instance()->backup_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup1_prepare_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
        }

        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->HandleMessage(leader_prepare_msg2);
        auto backup2_prepare_msg = bft::BftManager::Instance()->backup_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup2_prepare_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
        }

        // precommit
        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->HandleMessage(backup1_prepare_msg);
        bft::BftManager::Instance()->HandleMessage(backup2_prepare_msg);

        auto leader_precommit_msg = bft::BftManager::Instance()->leader_precommit_msg_;
        auto leader_precommit_msg2 = bft::BftManager::Instance()->leader_precommit_msg_;
        ASSERT_TRUE(leader_precommit_msg.has_data());
        ASSERT_TRUE(leader_precommit_msg2.has_data());

        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kRootCongressNetworkId);
        ResetBftSecret(bft_gid, network::kRootCongressNetworkId, common::GlobalInfo::Instance()->id());
        bft::BftManager::Instance()->HandleMessage(leader_precommit_msg);
        AddNewTxToTxPool(tx_bft.to_tx().block().tx_list(0));
        auto backup1_precommit_msg = bft::BftManager::Instance()->backup_precommit_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup1_precommit_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
        }

        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kRootCongressNetworkId);
        ResetBftSecret(bft_gid, network::kRootCongressNetworkId, common::GlobalInfo::Instance()->id());
        bft::BftManager::Instance()->HandleMessage(leader_precommit_msg2);
        auto backup2_precommit_msg = bft::BftManager::Instance()->backup_precommit_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup2_precommit_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
        }

        // commit
        uint32_t member_index = MemberManager::Instance()->GetMemberIndex(
            network::kRootCongressNetworkId,
            common::GlobalInfo::Instance()->id());
        auto mem_ptr = MemberManager::Instance()->GetMember(network::kRootCongressNetworkId, member_index);
        auto bft_ptr = bft::BftManager::Instance()->bft_hash_map_[bft_gid];

        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->HandleMessage(backup1_precommit_msg);
        bft::BftManager::Instance()->HandleMessage(backup2_precommit_msg);
        auto leader_commit_msg = bft::BftManager::Instance()->leader_commit_msg_;
        auto leader_commit_msg2 = bft::BftManager::Instance()->leader_commit_msg_;
        ASSERT_TRUE(leader_commit_msg.has_data());
        ASSERT_TRUE(leader_commit_msg2.has_data());

        *broadcast_msg = bft::BftManager::Instance()->root_leader_broadcast_msg_;

        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid] = bft_ptr;
        bft::BftManager::Instance()->HandleMessage(leader_commit_msg);
        SetGloableInfo("22345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kRootCongressNetworkId);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid] = bft_ptr;
        bft::BftManager::Instance()->HandleMessage(leader_commit_msg2);

        // check broadcast msg
        auto leader_broadcast_msg = bft::BftManager::Instance()->root_leader_broadcast_msg_;
        ASSERT_EQ(leader_broadcast_msg.type(), common::kBftMessage);
        protobuf::BftMessage bft_msg_t;
        ASSERT_TRUE(bft_msg_t.ParseFromString(leader_broadcast_msg.data()));
        bft::protobuf::TxBft tx_bft_t;
        ASSERT_TRUE(tx_bft_t.ParseFromString(bft_msg_t.data()));
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).amount(), tx_bft_t.to_tx().block().tx_list(0).amount());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).from(), tx_bft_t.to_tx().block().tx_list(0).from());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).to(), tx_bft_t.to_tx().block().tx_list(0).to());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).from_pubkey(), tx_bft_t.to_tx().block().tx_list(0).from_pubkey());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).from_sign(), tx_bft_t.to_tx().block().tx_list(0).from_sign());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).gid(), tx_bft_t.to_tx().block().tx_list(0).gid());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).attr_size(), tx_bft_t.to_tx().block().tx_list(0).attr_size());

        // hash128(gid + from + to + amount + type + attrs(k:v))
        tx_bft_t.mutable_to_tx()->mutable_block()->mutable_tx_list(0)->set_type(tx_bft.to_tx().block().tx_list(0).type());
        ASSERT_EQ(tx_bft.to_tx().block().tx_list(0).type(), tx_bft_t.to_tx().block().tx_list(0).type());
        ASSERT_EQ(GetTxMessageHash(tx_bft.to_tx().block().tx_list(0)), GetTxMessageHash(tx_bft_t.to_tx().block().tx_list(0)));
    }

    void NewAccountDestNetworkTransfer(
            bool is_from_root,
            uint32_t tx_type,
            bool just_to_id,
            transport::protobuf::Header& root_leader_msg,
            const std::string& from_prikey,
            const std::string& to_prikey,
            std::map<std::string, std::string>& attrs,
            transport::protobuf::Header* leader_broadcast_msg) {
        // root create new account and add to consensus network
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(root_leader_msg);
        if (tx_type == common::kConsensusCreateContract) {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(root_leader_msg.data()));
            protobuf::TxBft tx_bft;
            ASSERT_TRUE(tx_bft.ParseFromString(bft_msg.data()));
            auto src_block = tx_bft.to_tx().block();
            auto& tx_list =  tx_bft.to_tx().block().tx_list();
            std::string contract_address;
            std::string tx_bytes_code;
            for (int32_t i = 0; i < tx_bft.to_tx().block().tx_list(0).attr_size(); ++i) {
                if (tx_bft.to_tx().block().tx_list(0).attr(i).key() == bft::kContractBytesCode) {
                    contract_address = security::Secp256k1::Instance()->GetContractAddress(
                        tx_bft.to_tx().block().tx_list(0).from(),
                        tx_bft.to_tx().block().tx_list(0).gid(),
                        tx_bft.to_tx().block().tx_list(0).attr(i).value());
                    tx_bytes_code = tx_bft.to_tx().block().tx_list(0).attr(i).value();
                }
            }

            ASSERT_EQ(contract_address, tx_bft.to_tx().block().tx_list(0).to());
            auto contract_addr_info = block::AccountManager::Instance()->GetAcountInfo(contract_address);
            ASSERT_TRUE(contract_addr_info != nullptr);
            uint32_t address_type = block::kNormalAddress;
            std::string bytes_code;
            std::string owner;
            ASSERT_EQ(contract_addr_info->GetAddressType(&address_type), block::kBlockSuccess);
            ASSERT_EQ(contract_addr_info->GetBytesCode(&bytes_code), block::kBlockSuccess);
            ASSERT_EQ(contract_addr_info->GetAttrValue(block::kFieldContractOwner, &owner), block::kBlockSuccess);
            ASSERT_EQ(address_type, block::kContractAddress);
            ASSERT_EQ(bytes_code, tx_bytes_code);
            ASSERT_EQ(owner, tx_bft.to_tx().block().tx_list(0).from());
            attrs["res_contract_addr"] = contract_address;
            return;
        }

        usleep(bft::kBftStartDeltaTime);
        ASSERT_EQ(bft::BftManager::Instance()->StartBft(""), kBftSuccess);

        auto bft_gid = common::GlobalInfo::Instance()->gid_hash_ +
            std::to_string(common::GlobalInfo::Instance()->gid_idx_ - 1);
        auto iter = bft::BftManager::Instance()->bft_hash_map_.find(bft_gid);
        ASSERT_TRUE(iter != bft::BftManager::Instance()->bft_hash_map_.end());

        auto leader_prepare_msg = bft::BftManager::Instance()->leader_prepare_msg_;
        auto leader_prepare_msg2 = bft::BftManager::Instance()->leader_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(leader_prepare_msg.data()));
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(leader_prepare_msg);
        auto backup1_prepare_msg = bft::BftManager::Instance()->backup_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup1_prepare_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(leader_prepare_msg2);
        auto backup2_prepare_msg = bft::BftManager::Instance()->backup_prepare_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup2_prepare_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        // precommit
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(backup1_prepare_msg);
        bft::BftManager::Instance()->HandleMessage(backup2_prepare_msg);

        auto leader_precommit_msg = bft::BftManager::Instance()->leader_precommit_msg_;
        auto leader_precommit_msg2 = bft::BftManager::Instance()->leader_precommit_msg_;
        ASSERT_TRUE(leader_precommit_msg.has_data());
        ASSERT_TRUE(leader_precommit_msg2.has_data());

        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(leader_precommit_msg.data()));
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kConsensusShardBeginNetworkId);
        ResetBftSecret(bft_gid, network::kConsensusShardBeginNetworkId, common::GlobalInfo::Instance()->id());
        bft::BftManager::Instance()->HandleMessage(leader_precommit_msg);
        auto backup1_precommit_msg = bft::BftManager::Instance()->backup_precommit_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup1_precommit_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kConsensusShardBeginNetworkId);
        ResetBftSecret(bft_gid, network::kConsensusShardBeginNetworkId, common::GlobalInfo::Instance()->id());
        bft::BftManager::Instance()->HandleMessage(leader_precommit_msg2);
        auto backup2_precommit_msg = bft::BftManager::Instance()->backup_precommit_msg_;
        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(backup2_precommit_msg.data()));
            ASSERT_TRUE(bft_msg.agree());
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        // commit
        std::string to_id = GetIdByPrikey(to_prikey);
        if (just_to_id) {
            to_id = to_prikey;
        }

        uint64_t src_balance = 0;
        {
            auto to_acc_info = block::AccountManager::Instance()->GetAcountInfo(to_id);
            ASSERT_TRUE(to_acc_info != nullptr);
            src_balance = to_acc_info->balance_;
        }

        uint32_t member_index = MemberManager::Instance()->GetMemberIndex(network::kConsensusShardBeginNetworkId, common::GlobalInfo::Instance()->id());
        auto mem_ptr = MemberManager::Instance()->GetMember(network::kConsensusShardBeginNetworkId, member_index);
        auto bft_ptr = bft::BftManager::Instance()->bft_hash_map_[bft_gid];

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->HandleMessage(backup1_precommit_msg);
        bft::BftManager::Instance()->HandleMessage(backup2_precommit_msg);
        auto leader_commit_msg = bft::BftManager::Instance()->leader_commit_msg_;
        auto leader_commit_msg2 = bft::BftManager::Instance()->leader_commit_msg_;
        ASSERT_TRUE(leader_commit_msg.has_data());
        ASSERT_TRUE(leader_commit_msg2.has_data());

        {
            protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(leader_commit_msg.data()));
            ASSERT_EQ(bft_msg.gid(), bft_gid);
        }

        {
            auto to_acc_info = block::AccountManager::Instance()->GetAcountInfo(to_id);
            db::DbWriteBach db_batch;
            to_acc_info->SetBalance(src_balance, db_batch);
            db::Db::Instance()->Put(db_batch);
        }

        *leader_broadcast_msg = bft::BftManager::Instance()->to_leader_broadcast_msg_;
        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485161e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid] = bft_ptr;
        bft::BftManager::Instance()->HandleMessage(leader_commit_msg);
        {
            auto to_acc_info = block::AccountManager::Instance()->GetAcountInfo(to_id);
            db::DbWriteBach db_batch;
            to_acc_info->SetBalance(src_balance, db_batch);
            db::Db::Instance()->Put(db_batch);
        }

        SetGloableInfo("12345f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485162e", network::kConsensusShardBeginNetworkId);
        bft::BftManager::Instance()->bft_hash_map_[bft_gid] = bft_ptr;
        bft::BftManager::Instance()->HandleMessage(leader_commit_msg2);
    }

    std::string GetIdByPrikey(const std::string& private_key) {
        security::PrivateKey prikey(private_key);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        EXPECT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
        std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
        return id;
    }

    void Transaction(
            const std::string& from_prikey,
            const std::string& to_prikey,
            uint64_t amount,
            uint64_t gas_limit,
            uint32_t tx_type,
            bool call_to,
            bool just_to_id,
            std::map<std::string, std::string>& attrs) {
        transport::protobuf::Header broadcast_msg;
        Transfer(from_prikey, to_prikey, amount, gas_limit, tx_type, just_to_id, attrs, &broadcast_msg);
        if (call_to) {
            bft::protobuf::BftMessage bft_msg;
            ASSERT_TRUE(bft_msg.ParseFromString(broadcast_msg.data()));
            ASSERT_TRUE(broadcast_msg.IsInitialized());
            uint32_t des_network_id = dht::DhtKeyManager::DhtKeyGetNetId(broadcast_msg.des_dht_key());
            if (des_network_id == network::kRootCongressNetworkId) {
                transport::protobuf::Header to_root_broadcast_msg;
                CreateNewAccount(from_prikey, to_prikey, broadcast_msg, &to_root_broadcast_msg);
                ASSERT_TRUE(to_root_broadcast_msg.IsInitialized());
                transport::protobuf::Header tmp_broadcast_msg;
                NewAccountDestNetworkTransfer(true, tx_type, just_to_id, to_root_broadcast_msg, from_prikey, to_prikey, attrs, &tmp_broadcast_msg);
            } else {
                transport::protobuf::Header tmp_broadcast_msg;
                NewAccountDestNetworkTransfer(false, tx_type, just_to_id, broadcast_msg, from_prikey, to_prikey, attrs, &tmp_broadcast_msg);
            }
        }
    }

    uint64_t GetBalanceByPrikey(const std::string& prikey) {
        auto account_info = block::AccountManager::Instance()->GetAcountInfo(GetIdByPrikey(prikey));
        if (account_info == nullptr) {
            return common::kInvalidUint64;
        }

        return account_info->balance_;
    }

    void InitOfflineTransferContract(
            std::string* contract_address,
            const std::string& bytes_code,
            uint64_t owner_balance,
            uint64_t contract_balance,
            uint64_t caller_balance) {
        {
            std::string from_prikey = common::Encode::HexDecode(
                "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
            std::string to_prikey = common::Encode::HexDecode(
                "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
            uint64_t from_balance = GetBalanceByPrikey(from_prikey);
            uint64_t to_balance = GetBalanceByPrikey(to_prikey);
            uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
            ASSERT_EQ(from_balance, init_balance);
            ASSERT_EQ(to_balance, common::kInvalidUint64);
            uint64_t all_amount = 0;
            uint64_t amount = owner_balance;
            uint64_t all_gas = 0;
            all_amount += amount;
            all_gas += bft::kTransferGas;
            std::map<std::string, std::string> attrs;
            Transaction(
                from_prikey,
                to_prikey,
                amount,
                all_gas + 1,
                common::kConsensusTransaction,
                true,
                false,
                attrs);
            from_balance = GetBalanceByPrikey(from_prikey);
            to_balance = GetBalanceByPrikey(to_prikey);
            ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
            ASSERT_EQ(to_balance, all_amount);
        }

        // create contract
        {
            std::string from_prikey = common::Encode::HexDecode(
                "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
            uint64_t init_balance = GetBalanceByPrikey(from_prikey);
            uint64_t all_amount = 0;
            uint64_t amount = 0;
            uint64_t all_gas = 0;
            all_gas += bft::kTransferGas;
            std::map<std::string, std::string> attrs;
            attrs.insert(std::make_pair(kContractBytesCode, bytes_code));
            all_gas += (kContractBytesCode.size() + attrs[kContractBytesCode].size()) *
                bft::kKeyValueStorageEachBytes;
            Transaction(
                from_prikey,
                "",
                amount,
                all_gas + 1,
                common::kConsensusCreateContract,
                true,
                false,
                attrs);
            uint64_t from_balance = GetBalanceByPrikey(from_prikey);
            ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
            *contract_address = attrs["res_contract_addr"];
        }

        // transfer to contract address
        {
            std::string from_prikey = common::Encode::HexDecode(
                "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
            std::string to_prikey = *contract_address;
            uint64_t init_balance = GetBalanceByPrikey(from_prikey);
            uint64_t all_amount = 0;
            uint64_t amount = contract_balance;
            uint64_t all_gas = 0;
            all_amount += amount;
            all_gas += bft::kTransferGas;
            std::map<std::string, std::string> attrs;
            Transaction(from_prikey, to_prikey, amount, all_gas + 1, common::kConsensusTransaction, true, true, attrs);
            auto from_balance = GetBalanceByPrikey(from_prikey);
            auto contract_info = block::AccountManager::Instance()->GetAcountInfo(*contract_address);
            ASSERT_TRUE(contract_info != nullptr);
            uint64_t to_balance;
            ASSERT_EQ(contract_info->GetBalance(&to_balance), block::kBlockSuccess);
            ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
            ASSERT_EQ(to_balance, all_amount);
        }

        // create contract caller
        {
            std::string from_prikey = common::Encode::HexDecode(
                "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
            std::string to_prikey = common::Encode::HexDecode(
                "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
            uint64_t init_balance = GetBalanceByPrikey(from_prikey);
            uint64_t to_balance = GetBalanceByPrikey(to_prikey);
            ASSERT_EQ(to_balance, common::kInvalidUint64);
            uint64_t all_amount = 0;
            uint64_t amount = caller_balance;
            uint64_t all_gas = 0;
            all_amount += amount;
            all_gas += bft::kTransferGas;
            std::map<std::string, std::string> attrs;
            Transaction(
                from_prikey,
                to_prikey,
                amount,
                all_gas + 1,
                common::kConsensusTransaction,
                true,
                false,
                attrs);
            auto from_balance = GetBalanceByPrikey(from_prikey);
            to_balance = GetBalanceByPrikey(to_prikey);
            ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
            ASSERT_EQ(to_balance, all_amount);
        }
    }

private:
    static std::map<uint32_t, std::string> pool_index_map_;
};

std::map<uint32_t, std::string> TestBftManager::pool_index_map_;

TEST_F(TestBftManager, RootCreateNewAccount) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    std::string to_prikey = common::Encode::HexDecode(
        "11115f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t to_balance = GetBalanceByPrikey(to_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    ASSERT_EQ(to_balance, common::kInvalidUint64);
    uint64_t all_amount = 0;
    uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
    uint64_t all_gas = 0;
    all_amount += amount;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    Transaction(
        from_prikey, to_prikey, amount, 1000000,
        common::kConsensusTransaction, true, false, attrs);
    for (uint32_t i = 0; i < 10; ++i) {
        all_amount += amount;
        all_gas += bft::kTransferGas;
        Transaction(
            from_prikey, to_prikey, amount, 1000000,
            common::kConsensusTransaction, true, false, attrs);
    }

    from_balance = GetBalanceByPrikey(from_prikey);
    to_balance = GetBalanceByPrikey(to_prikey);
    ASSERT_EQ(from_balance, init_balance - all_amount - all_gas * common::GlobalInfo::Instance()->gas_price());
    ASSERT_EQ(to_balance, all_amount);
}

TEST_F(TestBftManager, TransferGasLimitError) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    std::string to_prikey = common::Encode::HexDecode(
        "11115f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t to_balance = GetBalanceByPrikey(to_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    ASSERT_EQ(to_balance, common::kInvalidUint64);
    uint64_t all_amount = 0;
    uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
    uint64_t all_gas = 0;
    all_amount += amount;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    Transaction(
        from_prikey, to_prikey, amount, 100,
        common::kConsensusTransaction, false, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    to_balance = GetBalanceByPrikey(to_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price());
    ASSERT_EQ(to_balance, common::kInvalidUint64);
}

TEST_F(TestBftManager, TransferGasLimitJustOk) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    std::string to_prikey = common::Encode::HexDecode(
        "11115f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t to_balance = GetBalanceByPrikey(to_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    ASSERT_EQ(to_balance, common::kInvalidUint64);
    uint64_t all_amount = 0;
    uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
    uint64_t all_gas = 0;
    all_amount += amount;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    Transaction(
        from_prikey, to_prikey, amount, all_gas,
        common::kConsensusTransaction, true, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    to_balance = GetBalanceByPrikey(to_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
    ASSERT_EQ(to_balance, all_amount);
}

TEST_F(TestBftManager, TransferGasLimitCover) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    std::string to_prikey = common::Encode::HexDecode(
        "11115f72efffee770264ec22dc21c9d2bab63aec39941aad09acda57b485164e");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t to_balance = GetBalanceByPrikey(to_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    ASSERT_EQ(to_balance, common::kInvalidUint64);
    uint64_t all_amount = 0;
    uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
    uint64_t all_gas = 0;
    all_amount += amount;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    for (int i = 0; i < 10; ++i) {
        attrs.insert(std::make_pair(
            common::Random::RandomString(i + 1),
            common::Random::RandomString(i + 2)));
        all_gas += (i + 1 + i + 2) * bft::kKeyValueStorageEachBytes;
    }

    Transaction(from_prikey, to_prikey, amount, all_gas + 1,
        common::kConsensusTransaction, true, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    to_balance = GetBalanceByPrikey(to_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
    ASSERT_EQ(to_balance, all_amount);
}

TEST_F(TestBftManager, TransferTestSetFromAttrsOk) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    uint64_t all_amount = 0;
    uint64_t all_gas = 0;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    for (int i = 0; i < 10; ++i) {
        attrs.insert(std::make_pair(
            common::Random::RandomString(i + 1),
            common::Random::RandomString(i + 2)));
        all_gas += (i + 1 + i + 2) * bft::kKeyValueStorageEachBytes;
    }

    Transaction(from_prikey, "", 0, all_gas, common::kConsensusTransaction, false, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
    auto from_account = block::AccountManager::Instance()->GetAcountInfo(
        GetIdByPrikey(from_prikey));
    for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
        std::string value;
        from_account->GetAttrValue(iter->first, &value);
        ASSERT_EQ(iter->second, value);
    }
}

TEST_F(TestBftManager, TransferTestSetFromAttrsGasError) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    uint64_t all_amount = 0;
    uint64_t all_gas = 0;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    for (int i = 0; i < 10; ++i) {
        attrs.insert(std::make_pair(
            common::Random::RandomString(i + 1),
            common::Random::RandomString(i + 2)));
        all_gas += (i + 1 + i + 2) * bft::kKeyValueStorageEachBytes;
    }

    Transaction(from_prikey, "", 0, all_gas - 1, common::kConsensusTransaction, false, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
    auto from_account = block::AccountManager::Instance()->GetAcountInfo(
        GetIdByPrikey(from_prikey));
    for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
        std::string value;
        from_account->GetAttrValue(iter->first, &value);
        ASSERT_TRUE(value.empty());
    }
}

TEST_F(TestBftManager, TransferTestSetFromAttrsGasCover) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    uint64_t all_amount = 0;
    uint64_t all_gas = 0;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    for (int i = 0; i < 10; ++i) {
        attrs.insert(std::make_pair(
            common::Random::RandomString(i + 1),
            common::Random::RandomString(i + 2)));
        all_gas += (i + 1 + i + 2) * bft::kKeyValueStorageEachBytes;
    }

    Transaction(from_prikey, "", 0, all_gas + 1,
        common::kConsensusTransaction, false, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
    auto from_account = block::AccountManager::Instance()->GetAcountInfo(
        GetIdByPrikey(from_prikey));
    for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
        std::string value;
        from_account->GetAttrValue(iter->first, &value);
        ASSERT_EQ(iter->second, value);
    }
}

TEST_F(TestBftManager, CreateContractOk) {
    std::string from_prikey = common::Encode::HexDecode(
        "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
    uint64_t from_balance = GetBalanceByPrikey(from_prikey);
    uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
    ASSERT_EQ(from_balance, init_balance);
    uint64_t all_amount = 0;
    uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
    uint64_t all_gas = 0;
    all_amount += amount;
    all_gas += bft::kTransferGas;
    std::map<std::string, std::string> attrs;
    attrs.insert(std::make_pair(kContractBytesCode, "kContractBytesCode"));
    all_gas += (kContractBytesCode.size() + attrs[kContractBytesCode].size())*
        bft::kKeyValueStorageEachBytes;
    for (int i = 0; i < 10; ++i) {
        attrs.insert(std::make_pair(
            common::Random::RandomString(i + 1),
            common::Random::RandomString(i + 2)));
        all_gas += (i + 1 + i + 2) * bft::kKeyValueStorageEachBytes;
    }

    Transaction(
        from_prikey, "", amount, all_gas + 1,
        common::kConsensusCreateContract, true, false, attrs);
    from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
}

TEST_F(TestBftManager, TestWithTvm) {
    std::string private_key = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
    security::PrivateKey prikey(private_key);
    security::PublicKey pubkey(prikey);
    std::string pubkey_str;
    EXPECT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
    EXPECT_EQ(pubkey_str.size(), 65);
    EXPECT_EQ(common::Encode::HexEncode(
        security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str)),
        "b8ce9ab6943e0eced004cde8e3bbed6568b2fa01");

    std::string public_key;
    EXPECT_TRUE(security::Secp256k1::Instance()->ToPublic(
        private_key,
        SECP256K1_EC_UNCOMPRESSED,
        &public_key));
    EXPECT_EQ(public_key.size(), 65);
    ASSERT_EQ(pubkey_str, public_key);
}

TEST_F(TestBftManager, InitBft) {
    BftManager bft_manager;
    transport::protobuf::Header msg;
    msg.set_src_dht_key("dht_key");
    uint32_t des_net_id = common::GlobalInfo::Instance()->network_id();
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid("gid");
    bft_msg.set_rand(0);
    bft_msg.set_bft_step(bft::kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    security::PrivateKey private_key;
    security::PublicKey pubkey(private_key);
    std::string pubkey_str;
    ASSERT_EQ(pubkey.Serialize(pubkey_str, false), security::kPublicKeyUncompressSize);
    std::string id = security::Secp256k1::Instance()->ToAddressWithPublicKey(pubkey_str);
    bft_msg.set_node_id(id);
    bft_msg.set_pubkey(pubkey_str);
    bft::protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(common::CreateGID(pubkey_str));
    new_tx->set_from(id);
    new_tx->set_from_pubkey(pubkey_str);
    new_tx->set_to("to");
    new_tx->set_amount(1000000);
    new_tx->set_type(common::kConsensusTransaction);
    auto hash128 = GetTxMessageHash(*new_tx);
    auto tx_data = tx_bft.SerializeAsString();
    bft_msg.set_data(tx_data);
    security::Signature sign;
    ASSERT_TRUE(security::Schnorr::Instance()->Sign(
        hash128,
        private_key,
        pubkey,
        sign));
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
    auto account_info = block::AccountManager::Instance()->GetAcountInfo(id);
    EXPECT_EQ(account_info, nullptr);
    EXPECT_EQ(bft_manager.InitBft(msg, bft_msg), kBftNoNewTxs);
    EXPECT_FALSE(bft::MemberManager::Instance()->IsLeader(
        network::kConsensusShardBeginNetworkId,
        common::GlobalInfo::Instance()->id(),
        0));
}

TEST_F(TestBftManager, TestExecution) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    // maybe not ok, contract addr prikey: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8704
    
    // create owner and transfer tenon to it
    {
        std::string from_prikey = common::Encode::HexDecode(
            "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
        std::string to_prikey = common::Encode::HexDecode(
            "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
        uint64_t from_balance = GetBalanceByPrikey(from_prikey);
        uint64_t to_balance = GetBalanceByPrikey(to_prikey);
        uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
        ASSERT_EQ(from_balance, init_balance);
        ASSERT_EQ(to_balance, common::kInvalidUint64);
        uint64_t all_amount = 0;
        uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
        uint64_t all_gas = 0;
        all_amount += amount;
        all_gas += bft::kTransferGas;
        std::map<std::string, std::string> attrs;
        Transaction(
            from_prikey,
            to_prikey,
            amount,
            all_gas + 1,
            common::kConsensusTransaction,
            true,
            false,
            attrs);
        from_balance = GetBalanceByPrikey(from_prikey);
        to_balance = GetBalanceByPrikey(to_prikey);
        ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
        ASSERT_EQ(to_balance, all_amount);
    }
    

    // create contract
    std::string contract_addr;
    {
        std::string from_prikey = common::Encode::HexDecode(
            "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
        uint64_t init_balance = GetBalanceByPrikey(from_prikey);
        uint64_t all_amount = 0;
        uint64_t amount = 0;
        uint64_t all_gas = 0;
        all_gas += bft::kTransferGas;
        std::map<std::string, std::string> attrs;
        attrs.insert(std::make_pair(kContractBytesCode, common::Encode::HexDecode(
            "60806040523480156100115760006000fd5b50600436106100465760003560e01c806"
            "341c0e1b51461004c578063a90ae88714610056578063cfb5192814610072576100465"
            "65b60006000fd5b6100546100a2565b005b610070600480360381019061006b9190610"
            "402565b61011a565b005b61008c600480360381019061008791906103be565b61029c5"
            "65b604051610099919061048d565b60405180910390f35b600060009054906101000a9"
            "00473ffffffffffffffffffffffffffffffffffffffff1673fffffffffffffffffffff"
            "fffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141"
            "5156100ff5760006000fd5b3373ffffffffffffffffffffffffffffffffffffffff16f"
            "f5b565b6000601b905060007f3d584400dc77e383a2a2860d15fd181b1c36117d7b6c1"
            "e5d54e2f21d9491b66e60001b905060007f043a539fab3f2e42ba806da59b30e100077"
            "a7dba7439de3fce427eaa75dce5c460001b905060007ff559642966b18c5e58a82106d"
            "7cbb6dfaa449e1820dda477580b08bab68b93d560001b9050600060018286868660405"
            "1600081526020016040526040516101bd94939291906104a9565b60206040516020810"
            "39080840390855afa1580156101e0573d600060003e3d6000fd5b50505060206040510"
            "3519050600060009054906101000a900473fffffffffffffffffffffffffffffffffff"
            "fffff1673ffffffffffffffffffffffffffffffffffffffff168173fffffffffffffff"
            "fffffffffffffffffffffffff161415156102495760006000fd5b3373fffffffffffff"
            "fffffffffffffffffffffffffff166108fc89908115029060405160006040518083038"
            "1858888f19350505050158015610290573d600060003e3d6000fd5b5050505050505b5"
            "05050565b600060008290506000815114156102ba57600060001b9150506102c3565b6"
            "0208301519150505b9190505661063e565b60006102df6102da84610516565b6104ef5"
            "65b9050828152602081018484840111156102f85760006000fd5b61030384828561059"
            "e565b505b9392505050565b600061031f61031a84610548565b6104ef565b905082815"
            "2602081018484840111156103385760006000fd5b61034384828561059e565b505b939"
            "2505050565b600082601f83011215156103605760006000fd5b8135610370848260208"
            "6016102cc565b9150505b92915050565b600082601f830112151561038e5760006000f"
            "d5b813561039e84826020860161030c565b9150505b92915050565b600081359050610"
            "3b781610623565b5b92915050565b6000602082840312156103d15760006000fd5b600"
            "082013567ffffffffffffffff8111156103ec5760006000fd5b6103f88482850161037"
            "a565b9150505b92915050565b600060006000606084860312156104195760006000fd5"
            "b6000610427868287016103a8565b9350506020610438868287016103a8565b9250506"
            "04084013567ffffffffffffffff8111156104565760006000fd5b61046286828701610"
            "34c565b9150505b9250925092565b6104768161057a565b82525b5050565b610486816"
            "10590565b82525b5050565b60006020820190506104a2600083018461046d565b5b929"
            "15050565b60006080820190506104be600083018761046d565b6104cb6020830186610"
            "47d565b6104d8604083018561046d565b6104e5606083018461046d565b5b959450505"
            "05050565b60006104f961050b565b905061050582826105ae565b5b919050565b60006"
            "0405190505b90565b600067ffffffffffffffff821115610531576105306105e0565b5"
            "b61053a82610611565b90506020810190505b919050565b600067ffffffffffffffff8"
            "21115610563576105626105e0565b5b61056c82610611565b90506020810190505b919"
            "050565b60008190505b919050565b60008190505b919050565b600060ff821690505b9"
            "19050565b828183376000838301525b505050565b6105b782610611565b81018181106"
            "7ffffffffffffffff821117156105d6576105d56105e0565b5b80604052505b5050565"
            "b7f4e487b7100000000000000000000000000000000000000000000000000000000600"
            "052604160045260246000fd5b565b6000601f19601f83011690505b919050565b61062"
            "c81610585565b8114151561063a5760006000fd5b5b50565bfea264697066735822122"
            "05df1f066520c41781aa6e597f682192d353de3fdfe0f68038958a4170a2bf34264736"
            "f6c63430008030033")));
        all_gas += (kContractBytesCode.size() + attrs[kContractBytesCode].size()) *
            bft::kKeyValueStorageEachBytes;
        Transaction(
            from_prikey,
            "",
            amount,
            all_gas + 1,
            common::kConsensusCreateContract,
            true,
            false,
            attrs);
        uint64_t from_balance = GetBalanceByPrikey(from_prikey);
        ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
        contract_addr = attrs["res_contract_addr"];
    }

    // transfer to contract address
    {
        std::string from_prikey = common::Encode::HexDecode(
            "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
        std::string to_prikey = contract_addr;
        uint64_t init_balance = GetBalanceByPrikey(from_prikey);
        uint64_t all_amount = 0;
        uint64_t amount = 100llu * common::kTenonMiniTransportUnit;
        uint64_t all_gas = 0;
        all_amount += amount;
        all_gas += bft::kTransferGas;
        std::map<std::string, std::string> attrs;
        Transaction(from_prikey, to_prikey, amount, all_gas + 1, common::kConsensusTransaction, true, true, attrs);
        auto from_balance = GetBalanceByPrikey(from_prikey);
        auto contract_info = block::AccountManager::Instance()->GetAcountInfo(contract_addr);
        ASSERT_TRUE(contract_info != nullptr);
        uint64_t to_balance;
        ASSERT_EQ(contract_info->GetBalance(&to_balance), block::kBlockSuccess);
        ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
        ASSERT_EQ(to_balance, all_amount);
    }

    // create contract caller
    {
        std::string from_prikey = common::Encode::HexDecode(
            "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
        std::string to_prikey = common::Encode::HexDecode(
            "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
        uint64_t init_balance = GetBalanceByPrikey(from_prikey);
        uint64_t to_balance = GetBalanceByPrikey(to_prikey);
        ASSERT_EQ(to_balance, common::kInvalidUint64);
        uint64_t all_amount = 0;
        uint64_t amount = 10000llu * common::kTenonMiniTransportUnit;
        uint64_t all_gas = 0;
        all_amount += amount;
        all_gas += bft::kTransferGas;
        std::map<std::string, std::string> attrs;
        Transaction(
            from_prikey,
            to_prikey,
            amount,
            all_gas + 1,
            common::kConsensusTransaction,
            true,
            false,
            attrs);
        auto from_balance = GetBalanceByPrikey(from_prikey);
        to_balance = GetBalanceByPrikey(to_prikey);
        ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
        ASSERT_EQ(to_balance, all_amount);
    }

    // direct call contract
    {
        std::string from_prikey = common::Encode::HexDecode(
            "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
        tvm::Execution exec;
        std::string contract_address = contract_addr;
        std::string input = common::Encode::HexDecode(
            "a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
        std::string from = GetIdByPrikey(from_prikey);
        std::string to = contract_address;
        std::string origin_address = from;
        uint64_t value = 0;
        uint64_t gas_limit = 100000000;
        uint32_t depth = 0;
        evmc_result evmc_res = {};
        evmc::result res{ evmc_res };
        tvm::TenonHost tenon_host;
        auto caller_info = block::AccountManager::Instance()->GetAcountInfo(from);
        ASSERT_TRUE(caller_info != nullptr);
        uint64_t caller_balance = 0;
        ASSERT_EQ(caller_info->GetBalance(&caller_balance), block::kBlockSuccess);
        tenon_host.AddTmpAccountBalance(
            from,
            caller_balance);
        auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(
            contract_address);
        ASSERT_TRUE(contract_info != nullptr);
        uint64_t contract_balance = 0;
        ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
        tenon_host.AddTmpAccountBalance(
            contract_address,
            contract_balance);
        exec.execute(
            receive_pays,
            input,
            from,
            to,
            origin_address,
            value,
            gas_limit,
            depth,
            tvm::kJustCall,
            tenon_host,
            &res);
        ASSERT_EQ(res.status_code, EVMC_SUCCESS);
        ASSERT_EQ(tenon_host.accounts_.size(), 0);
        ASSERT_EQ(tenon_host.to_account_value_.size(), 1);

        std::cout << "from: " << common::Encode::HexEncode(from)
            << ", to(contract address): " << common::Encode::HexEncode(to)
            << ", owner: " << common::Encode::HexEncode(GetIdByPrikey(common::Encode::HexDecode("348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709")))
            << std::endl;
        auto iter = tenon_host.to_account_value_.begin();
        std::cout << "from: " << common::Encode::HexEncode(iter->first) << std::endl;
        auto sec_iter = iter->second.begin();
        std::cout << "to: " << common::Encode::HexEncode(sec_iter->first) << " : " << sec_iter->second << std::endl;
    }
}

TEST_F(TestBftManager, TestCallContractSuccess) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        100llu * common::kTenonMiniTransportUnit);
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    Transfer(from_prikey, contract_addr, 0, 100000000,
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, from_balance - kCallContractDefaultUseGas * common::GlobalInfo::Instance()->gas_price());

    // LockContract
    transport::protobuf::Header leader_init_msg;
    auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(contract_addr);
    uint64_t contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    ASSERT_TRUE(contract_info != nullptr);
    ASSERT_FALSE(contract_info->locked());
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, broadcast_msg, from_prikey, contract_addr, attrs, &leader_init_msg);
    ASSERT_TRUE(contract_info->locked());
    uint64_t new_contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance, new_contract_balance);

    // CallContract
    from_balance = GetBalanceByPrikey(from_prikey);
    transport::protobuf::Header leader_lock_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_init_msg, from_prikey, contract_addr, attrs, &leader_lock_msg);
    new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, from_balance - 98438453 * common::GlobalInfo::Instance()->gas_price() + 2643000000);

    // UnlockContract
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    transport::protobuf::Header leader_called_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_lock_msg, from_prikey, contract_addr, attrs, &leader_called_msg);
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance - 2643000000, new_contract_balance);
}

TEST_F(TestBftManager, TestCallContractCallerInitBalaceError) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        10000llu);
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    std::cout << "TTTTTTTTTTTTTTT get from balance: " << from_balance << std::endl;
    Transfer(from_prikey, contract_addr, 0, 100000000,
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, 0);
}

TEST_F(TestBftManager, TestCallContractCallerLockContractError) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        kCallContractDefaultUseGas * common::GlobalInfo::Instance()->gas_price() + 100);
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    std::cout << "TTTTTTTTTTTTTTT get from balance: " << from_balance << std::endl;
    Transfer(from_prikey, contract_addr, 0, kCallContractDefaultUseGas,
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, 100);
}

TEST_F(TestBftManager, TestCallContractCallerLockContractError1) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        (kCallContractDefaultUseGas + kTransferGas ) * common::GlobalInfo::Instance()->gas_price());
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    std::cout << "TTTTTTTTTTTTTTT get from balance: " << from_balance << std::endl;
    Transfer(from_prikey, contract_addr, 0, (kCallContractDefaultUseGas + kTransferGas),
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, kTransferGas * common::GlobalInfo::Instance()->gas_price());
}

TEST_F(TestBftManager, TestCallContractCallerLockContractError2) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        (kCallContractDefaultUseGas + kTransferGas) * common::GlobalInfo::Instance()->gas_price() + 1);
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    std::cout << "TTTTTTTTTTTTTTT get from balance: " << from_balance << std::endl;
    Transfer(from_prikey, contract_addr, 0,
        (kCallContractDefaultUseGas + kTransferGas),
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, kTransferGas * common::GlobalInfo::Instance()->gas_price() + 1);

    // LockContract
    transport::protobuf::Header leader_init_msg;
    auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(contract_addr);
    uint64_t contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    ASSERT_TRUE(contract_info != nullptr);
    ASSERT_FALSE(contract_info->locked());
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, broadcast_msg, from_prikey, contract_addr, attrs, &leader_init_msg);
    ASSERT_TRUE(contract_info->locked());
    uint64_t new_contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance, new_contract_balance);

    // CallContract
    from_balance = GetBalanceByPrikey(from_prikey);
    transport::protobuf::Header leader_lock_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_init_msg, from_prikey, contract_addr, attrs, &leader_lock_msg);
    new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, 1);
}

TEST_F(TestBftManager, TestCallContractCallerLockContractError3) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        (kCallContractDefaultUseGas + kTransferGas) * common::GlobalInfo::Instance()->gas_price() + 10000);
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    std::cout << "TTTTTTTTTTTTTTT get from balance: " << from_balance << std::endl;
    Transfer(from_prikey, contract_addr, 0,
        (kCallContractDefaultUseGas + kTransferGas),
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, kTransferGas * common::GlobalInfo::Instance()->gas_price() + 10000);

    // LockContract
    transport::protobuf::Header leader_init_msg;
    auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(contract_addr);
    uint64_t contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    ASSERT_TRUE(contract_info != nullptr);
    ASSERT_FALSE(contract_info->locked());
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, broadcast_msg, from_prikey, contract_addr, attrs, &leader_init_msg);
    ASSERT_TRUE(contract_info->locked());
    uint64_t new_contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance, new_contract_balance);

    // CallContract
    from_balance = GetBalanceByPrikey(from_prikey);
    transport::protobuf::Header leader_lock_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_init_msg, from_prikey, contract_addr, attrs, &leader_lock_msg);
    new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, 10000);
}

TEST_F(TestBftManager, TestCallContractCallerLockContractError4) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        receive_pays,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        (kCallContractDefaultUseGas + kTransferGas) * common::GlobalInfo::Instance()->gas_price() + 98438453 * common::GlobalInfo::Instance()->gas_price());
    // call contract
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    std::cout << "TTTTTTTTTTTTTTT get from balance: " << from_balance << std::endl;
    Transfer(from_prikey, contract_addr, 0,
        (kCallContractDefaultUseGas + kTransferGas + 98438453),
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, kTransferGas * common::GlobalInfo::Instance()->gas_price() + 984384530);

    // LockContract
    transport::protobuf::Header leader_init_msg;
    auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(contract_addr);
    uint64_t contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    ASSERT_TRUE(contract_info != nullptr);
    ASSERT_FALSE(contract_info->locked());
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, broadcast_msg, from_prikey, contract_addr, attrs, &leader_init_msg);
    ASSERT_TRUE(contract_info->locked());
    uint64_t new_contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance, new_contract_balance);

    // CallContract
    from_balance = GetBalanceByPrikey(from_prikey);
    transport::protobuf::Header leader_lock_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_init_msg, from_prikey, contract_addr, attrs, &leader_lock_msg);
    new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, 2658273200);

    // UnlockContract
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    transport::protobuf::Header leader_called_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_lock_msg, from_prikey, contract_addr, attrs, &leader_called_msg);
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance - 2643000000, new_contract_balance);
}

TEST_F(TestBftManager, TestContractCreateExcution) {
    // create owner
    {
        std::string from_prikey = common::Encode::HexDecode(
            "b6aaadbe30d002d7c532b95901949540f9213e740467461d540d9f3cc3efb4b6");
        std::string to_prikey = common::Encode::HexDecode(
            "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
        uint64_t from_balance = GetBalanceByPrikey(from_prikey);
        uint64_t to_balance = GetBalanceByPrikey(to_prikey);
        uint64_t init_balance = 21000000000llu * common::kTenonMiniTransportUnit / 64llu;
        ASSERT_EQ(from_balance, init_balance);
        ASSERT_EQ(to_balance, common::kInvalidUint64);
        uint64_t all_amount = 0;
        uint64_t amount = 10llu * common::kTenonMiniTransportUnit;
        uint64_t all_gas = 0;
        all_amount += amount;
        all_gas += bft::kTransferGas;
        std::map<std::string, std::string> attrs;
        Transaction(
            from_prikey,
            to_prikey,
            amount,
            all_gas + 1,
            common::kConsensusTransaction,
            true,
            false,
            attrs);
        from_balance = GetBalanceByPrikey(from_prikey);
        to_balance = GetBalanceByPrikey(to_prikey);
        ASSERT_EQ(from_balance, init_balance - all_gas * common::GlobalInfo::Instance()->gas_price() - all_amount);
        ASSERT_EQ(to_balance, all_amount);
    }

    // direct call contract to create
    {
        std::string from_prikey = common::Encode::HexDecode(
            "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709");
        tvm::Execution exec;
        std::string contract_address = "348ce564d427a3311b6536bbcff9390d69395b06";
        std::string input;
        std::string from = GetIdByPrikey(from_prikey);
        std::string to = contract_address;
        std::string origin_address = from;
        uint64_t value = 0;
        uint64_t gas_limit = 100000000000;
        uint32_t depth = 0;
        evmc_result evmc_res = {};
        evmc::result res{ evmc_res };
        tvm::TenonHost tenon_host;
        auto caller_info = block::AccountManager::Instance()->GetAcountInfo(from);
        ASSERT_TRUE(caller_info != nullptr);
        uint64_t caller_balance = 0;
        ASSERT_EQ(caller_info->GetBalance(&caller_balance), block::kBlockSuccess);
        tenon_host.AddTmpAccountBalance(
            from,
            caller_balance);
        exec.execute(
            ballot_str,
            input,
            from,
            to,
            origin_address,
            value,
            gas_limit,
            depth,
            tvm::kJustCreate,
            tenon_host,
            &res);
        ASSERT_EQ(res.status_code, EVMC_SUCCESS);
        ASSERT_EQ(tenon_host.accounts_.size(), 1);
        ASSERT_EQ(tenon_host.to_account_value_.size(), 0);
        for (auto account_iter = tenon_host.accounts_.begin(); account_iter != tenon_host.accounts_.end(); ++account_iter) {
            for (auto key_iter = account_iter->second.storage.begin(); key_iter != account_iter->second.storage.end(); ++key_iter) {
                std::cout << "id: " << common::Encode::HexEncode(std::string((char*)account_iter->first.bytes, sizeof(account_iter->first.bytes)))
                    << ", key: " << common::Encode::HexEncode(std::string((char*)key_iter->first.bytes, sizeof(key_iter->first.bytes)))
                    << ", value: " << common::Encode::HexEncode(std::string((char*)key_iter->second.value.bytes, sizeof(key_iter->second.value.bytes)))
                    << std::endl;
            }
        }

        std::cout << "from: " << common::Encode::HexEncode(from)
            << ", to(contract address): " << common::Encode::HexEncode(to)
            << ", owner: " << common::Encode::HexEncode(GetIdByPrikey(common::Encode::HexDecode("348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709")))
            << std::endl;
    }
}


TEST_F(TestBftManager, TestCallContractBallotSuccess) {
    // contract owner: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709
    // contract caller: 348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700
    std::string contract_addr;
    InitOfflineTransferContract(
        &contract_addr,
        ballot_str,
        100llu * common::kTenonMiniTransportUnit,
        90llu * common::kTenonMiniTransportUnit,
        100llu * common::kTenonMiniTransportUnit);
    // call contract construct
    transport::protobuf::Header broadcast_msg;
    std::string from_prikey = common::Encode::HexDecode(
        "348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8700");
    std::map<std::string, std::string> attrs;
    attrs[bft::kContractInputCode] = common::Encode::HexDecode("a90ae887000000000000000000000000000000000000000000000000000000009d88fac000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004129e687739c0fd3ceb3afe3bad915dd8994f9303e5d853589397c8abadb85a9e85e9c890353c564900a7f3dc6d1b7667e5af80035f63da7a9094bb054811ec7181c00000000000000000000000000000000000000000000000000000000000000");
    // Default caller init
    auto from_balance = GetBalanceByPrikey(from_prikey);
    Transfer(from_prikey, contract_addr, 0, 100000000,
        common::kConsensusCallContract, true, attrs, &broadcast_msg);
    auto new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, from_balance - kCallContractDefaultUseGas * common::GlobalInfo::Instance()->gas_price());

    // LockContract
    transport::protobuf::Header leader_init_msg;
    auto contract_info = block::AccountManager::Instance()->GetContractInfoByAddress(contract_addr);
    uint64_t contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    ASSERT_TRUE(contract_info != nullptr);
    ASSERT_FALSE(contract_info->locked());
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, broadcast_msg, from_prikey, contract_addr, attrs, &leader_init_msg);
    ASSERT_TRUE(contract_info->locked());
    uint64_t new_contract_balance = 0;
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance, new_contract_balance);

    // CallContract
    from_balance = GetBalanceByPrikey(from_prikey);
    transport::protobuf::Header leader_lock_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_init_msg, from_prikey, contract_addr, attrs, &leader_lock_msg);
    new_from_balance = GetBalanceByPrikey(from_prikey);
    ASSERT_EQ(new_from_balance, from_balance - 98438453 * common::GlobalInfo::Instance()->gas_price() + 2643000000);

    // UnlockContract
    ASSERT_EQ(contract_info->GetBalance(&contract_balance), block::kBlockSuccess);
    transport::protobuf::Header leader_called_msg;
    NewAccountDestNetworkTransfer(false, common::kConsensusCallContract,
        true, leader_lock_msg, from_prikey, contract_addr, attrs, &leader_called_msg);
    ASSERT_EQ(contract_info->GetBalance(&new_contract_balance), block::kBlockSuccess);
    ASSERT_EQ(contract_balance - 2643000000, new_contract_balance);
}

}  // namespace test

}  // namespace bft

}  // namespace tenon
