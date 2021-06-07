#include "init/genesis_block_init.h"

#include "common/encode.h"
#include "block/account_manager.h"
#include "init/init_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/bft_utils.h"
#include "bft/bft_manager.h"
#include "network/network_utils.h"
#include "root/root_utils.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/crypto_utils.h"
#include "security/secp256k1.h"
#include "timeblock/time_block_utils.h"
#include "timeblock/time_block_manager.h"

namespace tenon {

namespace init {

GenesisBlockInit::GenesisBlockInit() {}

GenesisBlockInit::~GenesisBlockInit() {}

int GenesisBlockInit::CreateGenesisBlocks(uint32_t net_id) {
    if (net_id == network::kRootCongressNetworkId) {
        return CreateRootGenesisBlocks();
    }

    return CreateShardGenesisBlocks(net_id);
}

int GenesisBlockInit::CreateRootGenesisBlocks() {
    uint64_t genesis_account_balance = 0llu;
    uint64_t all_balance = 0llu;
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        auto iter = root::kRootInitAccountAddressWithPoolIndexMap.find(i);
        std::string address = security::Secp256k1::Instance()->ToAddressWithPublicKey(iter->second);
        auto tx_info = tx_list->Add();
        tx_info->set_version(common::kTransactionVersion);
        tx_info->set_gid(common::CreateGID(""));
        tx_info->set_from(address);
        tx_info->set_from_pubkey("");
        tx_info->set_from_sign("");
        tx_info->set_to("");
        tx_info->set_amount(genesis_account_balance);
        tx_info->set_balance(genesis_account_balance);
        tx_info->set_gas_limit(0);
        tx_info->set_type(common::kConsensusCreateGenesisAcount);
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
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            iter->first,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != genesis_account_balance) {
            return kInitError;
        }

        all_balance += balance;
    }

    if (all_balance != common::kGenesisFoundationMaxTenon) {
        return kInitError;
    }

    // for root single block chain
    std::string root_pre_hash;
    {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        auto tx_info = tx_list->Add();
        tx_info->set_version(common::kTransactionVersion);
        tx_info->set_gid(common::CreateGID(""));
        tx_info->set_from(root::kRootChainSingleBlockTxAddress);
        tx_info->set_from_pubkey("");
        tx_info->set_from_sign("");
        tx_info->set_to("");
        tx_info->set_amount(0);
        tx_info->set_balance(0);
        tx_info->set_gas_limit(0);
        tx_info->set_type(common::kConsensusCreateGenesisAcount);
        tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        tenon_block.set_prehash("");
        tenon_block.set_version(common::kTransactionVersion);
        tenon_block.set_elect_ver(0);
        tenon_block.set_agg_pubkey("");
        tenon_block.set_agg_sign_challenge("");
        tenon_block.set_agg_sign_response("");
        tenon_block.set_pool_index(common::kRootChainPoolIndex);
        tenon_block.set_height(0);
        tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance), block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != 0) {
            return kInitError;
        }

        root_pre_hash = bft::GetBlockHash(tenon_block);
    }

    {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        auto tx_info = tx_list->Add();
        tx_info->set_version(common::kTransactionVersion);
        tx_info->set_gid(common::CreateGID(""));
        tx_info->set_from(root::kRootChainSingleBlockTxAddress);
        tx_info->set_from_pubkey("");
        tx_info->set_from_sign("");
        tx_info->set_to("");
        tx_info->set_amount(0);
        tx_info->set_balance(0);
        tx_info->set_gas_limit(0);
        tx_info->set_network_id(network::kConsensusShardBeginNetworkId);
        tx_info->set_type(common::kConsensusRootTimeBlock);
        tx_info->set_from(root::kRootChainSingleBlockTxAddress);
        tx_info->set_gas_limit(0llu);
        tx_info->set_amount(0);
        tx_info->set_network_id(network::kRootCongressNetworkId);
        auto all_exits_attr = tx_info->add_attr();
        all_exits_attr->set_key(tmblock::kAttrTimerBlock);
        auto now_tm = common::TimeUtils::TimestampSeconds() - tmblock::kTimeBlockCreatePeriodSeconds;
        all_exits_attr->set_value(std::to_string(now_tm));
        tenon_block.set_prehash(root_pre_hash);
        tenon_block.set_version(common::kTransactionVersion);
        tenon_block.set_elect_ver(0);
        tenon_block.set_agg_pubkey("");
        tenon_block.set_agg_sign_challenge("");
        tenon_block.set_agg_sign_response("");
        tenon_block.set_pool_index(common::kRootChainPoolIndex);
        tenon_block.set_height(1);
        tenon_block.set_network_id(common::GlobalInfo::Instance()->network_id());
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        tmblock::TimeBlockManager::Instance()->UpdateTimeBlock(1, now_tm);
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            common::kRootChainPoolIndex,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(root::kRootChainSingleBlockTxAddress);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != 0) {
            return kInitError;
        }
    }

    return kInitSuccess;
}

int GenesisBlockInit::CreateShardGenesisBlocks(uint32_t net_id) {
    uint64_t genesis_account_balance = common::kGenesisFoundationMaxTenon / pool_index_map_.size();
    uint64_t all_balance = 0llu;
    for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
        bft::protobuf::Block tenon_block;
        auto tx_list = tenon_block.mutable_tx_list();
        security::PrivateKey prikey(iter->second);
        security::PublicKey pubkey(prikey);
        std::string pubkey_str;
        if (pubkey.Serialize(pubkey_str, false) != security::kPublicKeyUncompressSize) {
            return kInitError;
        }

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
        tx_info->set_type(common::kConsensusCreateGenesisAcount);
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
        tenon_block.set_hash(bft::GetBlockHash(tenon_block));
        if (bft::BftManager::Instance()->AddGenisisBlock(tenon_block) != bft::kBftSuccess) {
            return kInitError;
        }

        std::string pool_hash;
        uint64_t pool_height = 0;
        uint64_t tm;
        int res = block::AccountManager::Instance()->GetBlockInfo(
            iter->first,
            &pool_height,
            &pool_hash,
            &tm);
        if (res != block::kBlockSuccess) {
            return kInitError;
        }

        auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(address);
        if (account_ptr == nullptr) {
            return kInitError;
        }

        uint64_t balance = 0;
        if (account_ptr->GetBalance(&balance) != block::kBlockSuccess) {
            return kInitError;
        }

        if (balance != genesis_account_balance) {
            return kInitError;
        }

        all_balance += balance;
    }

    if (all_balance != common::kGenesisFoundationMaxTenon) {
        return kInitError;
    }

    return kInitSuccess;
}

void GenesisBlockInit::InitGenesisAccount() {
    pool_index_map_.insert(std::make_pair(0, common::Encode::HexDecode("15e931b6f91e6027f3f4180a00bd6bfec18d420ae931ddbfc0c64699e092ee7e")));
    pool_index_map_.insert(std::make_pair(1, common::Encode::HexDecode("47058a8e0b8be811beaff5750f91b31ff0e13046f6b0b79da92b0f1cddacd298")));
    pool_index_map_.insert(std::make_pair(2, common::Encode::HexDecode("d08f88afb32d047ad56b09f5d627345bc8d88da60b99287246c1c7278eb949ab")));
    pool_index_map_.insert(std::make_pair(3, common::Encode::HexDecode("ef67b909654365acb19650940988c8d5256a9941bf2c84c43bc1996c98fe52be")));
    pool_index_map_.insert(std::make_pair(4, common::Encode::HexDecode("b1bd97f2ba10b17939d00c3dab97dfe8d9cfc79421ae5cbed47b698ca005cb35")));
    pool_index_map_.insert(std::make_pair(5, common::Encode::HexDecode("62de298659450dc889c8b4ffc90e565b5f4b38ee063da95f7346ad99dcded287")));
    pool_index_map_.insert(std::make_pair(6, common::Encode::HexDecode("90b4966e5a798a03df418e758994be94e3b39f40d56dd07daf3658cd7a06f453")));
    pool_index_map_.insert(std::make_pair(7, common::Encode::HexDecode("ce2d915cad73da8f7ce1b4b4bf2fceaa48d6b05d37513bf1f63491ec39922acf")));
    pool_index_map_.insert(std::make_pair(8, common::Encode::HexDecode("39bbc61095fe34f9b1f1cbbc4393c1920e3eb057a06d58723b14a4ee2ed9b48a")));
    pool_index_map_.insert(std::make_pair(9, common::Encode::HexDecode("256aad249e4a2c87f8063a19bcdc2a50c15c317e2aa6c584258b122a87e322b7")));
    pool_index_map_.insert(std::make_pair(10, common::Encode::HexDecode("c9b29da356345a1a5ab4a3385de1b17661e32a04ff204caa775021fd21502c31")));
    pool_index_map_.insert(std::make_pair(11, common::Encode::HexDecode("086ac8f2dd747d314e2b9dcce4acf50a250d5c65587f65c3bd747f713a51fd7a")));
    pool_index_map_.insert(std::make_pair(12, common::Encode::HexDecode("bf46e27d5b88e963d8f7b3728f66d2ba6bae31ea2034fd6be39f8ff81256c93d")));
    pool_index_map_.insert(std::make_pair(13, common::Encode::HexDecode("9417aba6d8ddddd4aa521abc752d3728c0ab438c6850a9033a5fe461d0c03876")));
    pool_index_map_.insert(std::make_pair(14, common::Encode::HexDecode("27f10c4e39437be8eabf38e152a3e7624a89d09e16f243cbe42e86e513272157")));
    pool_index_map_.insert(std::make_pair(15, common::Encode::HexDecode("2e514e75f02cb852855109257625c39572787328fdd9ff2e5686a29b8734e5ba")));
    pool_index_map_.insert(std::make_pair(16, common::Encode::HexDecode("035e1a591ab8820f3c14680e43a3f2d2080a6badacc79571a278fec62ac81f9d")));
    pool_index_map_.insert(std::make_pair(17, common::Encode::HexDecode("d0b3003ead53f77fc8cec813a10ac14c33a9d5beecae6abfa0ecd0f75fa9f481")));
    pool_index_map_.insert(std::make_pair(18, common::Encode::HexDecode("1a10bf0725038375bedba147b0fed7b9dad7327b7eb165b7478db1b486b4215c")));
    pool_index_map_.insert(std::make_pair(19, common::Encode::HexDecode("33b5b4c8633fd1bb401c1b90d74892cb93df905d032158b546b2098c9115e5ce")));
    pool_index_map_.insert(std::make_pair(20, common::Encode::HexDecode("6fb7a235865570bdfd58d2fe9b6753c3feaa3b61f97e752cf53a6d968d3b9136")));
    pool_index_map_.insert(std::make_pair(21, common::Encode::HexDecode("05da2322820e529543a36d7bd9358f8ca2cf06a17aa2de7d24c2061c4bec3596")));
    pool_index_map_.insert(std::make_pair(22, common::Encode::HexDecode("6fa75789e4f84666e9cd7bae1fe14236c4d9f5b626675337003efd7ffdb5f47e")));
    pool_index_map_.insert(std::make_pair(23, common::Encode::HexDecode("e54298eba416073c6c9cc1485c8ae6394c125278981adcc1cd6238a671d68979")));
    pool_index_map_.insert(std::make_pair(24, common::Encode::HexDecode("af49e6f7ef00bee11cddc3e69d26494c0980c5e5bbeb0bea324be173e2df20e0")));
    pool_index_map_.insert(std::make_pair(25, common::Encode::HexDecode("99f98f75e1ac526ce32b2843bd693a51dc8db50aab75cbe56d0af8c94ae1723b")));
    pool_index_map_.insert(std::make_pair(26, common::Encode::HexDecode("252be258cd4abb8964b6c424ad1641d7f7482af45ca8b8aa2be81a045f08ca65")));
    pool_index_map_.insert(std::make_pair(27, common::Encode::HexDecode("d225c903f0552c6ebe0869ed97747032c2a45117afca6dac68871b7c5dd8ba4f")));
    pool_index_map_.insert(std::make_pair(28, common::Encode::HexDecode("c8438e4bb9768dd7a8f7dc3f2c4b3a7c7fe082040826ed9899ffa7300dbea3ea")));
    pool_index_map_.insert(std::make_pair(29, common::Encode::HexDecode("de8b240cc82f58d512ed970bfc363f2e38f8de2ffa258e0518024fc8c92ac7b6")));
    pool_index_map_.insert(std::make_pair(30, common::Encode::HexDecode("4dd6ea46f4ae1448023031a163d21f56d6b30870fd7f29528507036b88c2f95f")));
    pool_index_map_.insert(std::make_pair(31, common::Encode::HexDecode("fb1a48bc9fb646d3563ed950903edf7a154b5fe215dbee81083ea55b3050ccef")));
    pool_index_map_.insert(std::make_pair(32, common::Encode::HexDecode("7c995290d11ce7465c0948ffc831ec1e710560a2ec73386acd404754643faedf")));
    pool_index_map_.insert(std::make_pair(33, common::Encode::HexDecode("f3225c0225a10b22068c79fa0034e8ed80ccf29fa17bf9584a43bf38ee2cf5ac")));
    pool_index_map_.insert(std::make_pair(34, common::Encode::HexDecode("41bb0f79206d88f19707a93475acae0377ae87c5ba4ed8c9ddb88fdca057db7b")));
    pool_index_map_.insert(std::make_pair(35, common::Encode::HexDecode("a941c8a835775f70a65f3662605cab30a31cc7b257792fdedc86c550fa224f6d")));
    pool_index_map_.insert(std::make_pair(36, common::Encode::HexDecode("bd341a10c6677e8fbfb1e73ee299678debe3e151217010c6714ce14927525702")));
    pool_index_map_.insert(std::make_pair(37, common::Encode::HexDecode("80512731558d21405ea3fd85e002f60ecc0b16246eeb31dace113a11e77b4feb")));
    pool_index_map_.insert(std::make_pair(38, common::Encode::HexDecode("2d66024f1db2f688ba95f9c751f44af2d28f36b1b2216aaf4ba5d8e0407488de")));
    pool_index_map_.insert(std::make_pair(39, common::Encode::HexDecode("75dadc65bdfe2bd6144906d474a8a98bb7ef56ad04f387a6ca0282064a635f30")));
    pool_index_map_.insert(std::make_pair(40, common::Encode::HexDecode("3b5591fdfe7f7546502bcab3448477487646ba25b910c6908826f4550c7c39a5")));
    pool_index_map_.insert(std::make_pair(41, common::Encode::HexDecode("2b71575b8f8699313fdd23ba86c7ec5b5612d747e26e4f2526513bf099ae624d")));
    pool_index_map_.insert(std::make_pair(42, common::Encode::HexDecode("4cbbb59ec4d722517cba0755dce9dcdcf73152cec74c022987c20a943a1d1872")));
    pool_index_map_.insert(std::make_pair(43, common::Encode::HexDecode("2b9dd5abc2269df13a1def09e225562e7d7269ea30d523ebfa01c68282362493")));
    pool_index_map_.insert(std::make_pair(44, common::Encode::HexDecode("a2244fffdc51ac704de2cb1c194e7e0d74455134ab58ed69a487b36dd06a3aac")));
    pool_index_map_.insert(std::make_pair(45, common::Encode::HexDecode("e1366f43af3fb008871c392056ac5be54eb8313e918479bf155d1bf00668b51d")));
    pool_index_map_.insert(std::make_pair(46, common::Encode::HexDecode("347bde4a4a2bc931b72fe054c252837bf8c6a1414ae4499d1cf7275ec4a2ed58")));
    pool_index_map_.insert(std::make_pair(47, common::Encode::HexDecode("34c001b96898b5ad86671450f67dadb6971f393c6299f977861e0eb975e22c60")));
    pool_index_map_.insert(std::make_pair(48, common::Encode::HexDecode("8762cb571f7d0ed8250c710a229b9a037d208d04ac506e2c3a2c2c9587e7b734")));
    pool_index_map_.insert(std::make_pair(49, common::Encode::HexDecode("20049c355dea9fff1d3dddc3001a8e976c0c640815332f66c8cd2a59e4e0646a")));
    pool_index_map_.insert(std::make_pair(50, common::Encode::HexDecode("b594cdf70afd0d8edf68e57870d7720ded38e3b94a110e9f403a3557ea56c629")));
    pool_index_map_.insert(std::make_pair(51, common::Encode::HexDecode("18ca654cb6c57524f6ab7f13b4b12258db2d4b7926c052b6a6f5e189dd7b2fb6")));
    pool_index_map_.insert(std::make_pair(52, common::Encode::HexDecode("ad3323f214ad361ee1bce9fcfb14d2fd3cf7e8885e428d518dad5f01264aa378")));
    pool_index_map_.insert(std::make_pair(53, common::Encode::HexDecode("ad5ce8def6e6f1683cfa5065b91a56cb6d66b6d81b82176b6ce1d0d5bffed3f5")));
    pool_index_map_.insert(std::make_pair(54, common::Encode::HexDecode("0deea1895d524fd47e7efdb3bb5013f5a3f26f268b15b1a0a2cc9158952c635a")));
    pool_index_map_.insert(std::make_pair(55, common::Encode::HexDecode("5c810741354ae7f72e464794ec1714838ee20c1792579f1d2b6b6d7c2013b8dd")));
    pool_index_map_.insert(std::make_pair(56, common::Encode::HexDecode("372c60308055b397262a6ea157f2029281d132bfd13d0cc83a1cb64cfc7416c3")));
    pool_index_map_.insert(std::make_pair(57, common::Encode::HexDecode("01bb7c0cac6cf89eb3c716d56af8e4edd760c6b21be1dd74d46664f56502fab5")));
    pool_index_map_.insert(std::make_pair(58, common::Encode::HexDecode("c28e2397d9bf98a6b25644b94c6be8612248c326415cc86fc5d17d0561b5bbb6")));
    pool_index_map_.insert(std::make_pair(59, common::Encode::HexDecode("19a5ee48660dd510cb85a0bbf3baa2d23a12c23c25b3cbcf525bf96c501c1080")));
    pool_index_map_.insert(std::make_pair(60, common::Encode::HexDecode("af0792dae45b33618b9b91abb06c56d893c44ff9f8e2771202c732abfc14ec10")));
    pool_index_map_.insert(std::make_pair(61, common::Encode::HexDecode("ac73e3cd050fd0a48afe199f6c3eac235dbc3851a36f65e85aead1e76702b6d1")));
    pool_index_map_.insert(std::make_pair(62, common::Encode::HexDecode("fc70655542635cc321733717d9b18c30290cd7c00268f15e1646f1184cf7cb20")));
    pool_index_map_.insert(std::make_pair(63, common::Encode::HexDecode("9fa8c6b13c2c477459c9ca6888c9254ec2f28e1b5a26c1aee0d770448ddbcd0c")));
    pool_index_map_.insert(std::make_pair(64, common::Encode::HexDecode("c4ca62221b2aa5d8814f98756ed4821d51d0bdd2cc920a0239e8f70510e5c2b6")));
    pool_index_map_.insert(std::make_pair(65, common::Encode::HexDecode("4eeec7f44290ea1cc09a867d5cadddaa4737ac4a902d1628543d8c49bbbe50b9")));
    pool_index_map_.insert(std::make_pair(66, common::Encode::HexDecode("643484b9643a8db945385be2be2937eeff8a52aa66a61af9cdc5800d86560ef6")));
    pool_index_map_.insert(std::make_pair(67, common::Encode::HexDecode("9ab38ae89aa5386a242ab46a73e397523b6eca80e06ede82cdbe111c3ad7afd0")));
    pool_index_map_.insert(std::make_pair(68, common::Encode::HexDecode("e1a2100640d469b7f7a7007e17f73796a2e50c95891738c00f7b9b6b7ba26fc5")));
    pool_index_map_.insert(std::make_pair(69, common::Encode::HexDecode("fb07be9a3c668cbd0c3c4c37912feb42b92644d8096eb4b311f2cb52064ef2d4")));
    pool_index_map_.insert(std::make_pair(70, common::Encode::HexDecode("b94f475fbfa9f6287139061726c17d6aabf1ffb6c1d97b9e39ed4edcb1a2721d")));
    pool_index_map_.insert(std::make_pair(71, common::Encode::HexDecode("f6c6d0b901eb8548d2261b92f8fe1240f5924c82b0f73756586f2d6797d5a9ee")));
    pool_index_map_.insert(std::make_pair(72, common::Encode::HexDecode("fe7fc5b4f87e216cc8dbbc34043eccf73baa17af63deb7eec88650bba4482034")));
    pool_index_map_.insert(std::make_pair(73, common::Encode::HexDecode("32ff0baececa13afd145a6e00f6a5bccb1361dbca12152de6f9e7287c780f59b")));
    pool_index_map_.insert(std::make_pair(74, common::Encode::HexDecode("04d134eb5ac4b750f92d9d03929ac334d5314e53473fe2f9ed70890f0eef980b")));
    pool_index_map_.insert(std::make_pair(75, common::Encode::HexDecode("3654d4f0c332e939320fe5d2755be97ca22cb1bf0f728c18d29f70d32ab97006")));
    pool_index_map_.insert(std::make_pair(76, common::Encode::HexDecode("58382001ffca79c57c996e574ce7f6bb544e1b5ac0e17a6564277d60a347953d")));
    pool_index_map_.insert(std::make_pair(77, common::Encode::HexDecode("d56b0695e87733dad383a59b718ec2964294f509f87b89696282fcc18181ec1d")));
    pool_index_map_.insert(std::make_pair(78, common::Encode::HexDecode("b592c6bd1cd6b75ec8f8b2b5bfd3e6cb1575bea232be20003daf0e23f0f5468d")));
    pool_index_map_.insert(std::make_pair(79, common::Encode::HexDecode("1f52d430ae11506e16c9ed6197d5eb4773722f59d5d75b34335218b012659afa")));
    pool_index_map_.insert(std::make_pair(80, common::Encode::HexDecode("a6f8b540aa45b1d7550ff9a5dee9c4874f7c3c7d14b21b003772dc70310335fa")));
    pool_index_map_.insert(std::make_pair(81, common::Encode::HexDecode("d91e6796a997a9a2f03d2efe12cbaf72042cd12e75575c49fc8d24899b5b468f")));
    pool_index_map_.insert(std::make_pair(82, common::Encode::HexDecode("7a0f9263eb844def856d0b3a42e85bc8635bd26ff335933b60bbc904f99dc34f")));
    pool_index_map_.insert(std::make_pair(83, common::Encode::HexDecode("618fa49e186a16f37c3e1d1105b4e3d3286f473b813a715e1ad2858e0268fdf5")));
    pool_index_map_.insert(std::make_pair(84, common::Encode::HexDecode("813ac1ddeb5cec1802f3d45d9a1407cdd40856a60f7f3ed89736f0e78503c2a5")));
    pool_index_map_.insert(std::make_pair(85, common::Encode::HexDecode("8aa26551eec55ae912739c5bd50d3b50ec4ebd7d824d287cc320e45e9ab42d71")));
    pool_index_map_.insert(std::make_pair(86, common::Encode::HexDecode("4ed7844312a7d4a6eecd699a1aa852c550a6d7bed18ab7413852b0b595870812")));
    pool_index_map_.insert(std::make_pair(87, common::Encode::HexDecode("0e254bafd25fe8a5d1ff305c84535339bbd8754d6e8c329a801db7d1d930e880")));
    pool_index_map_.insert(std::make_pair(88, common::Encode::HexDecode("599a5faee2d77a5795f891b5fff9c2d87c7ac8aae35bd6cfafff0f9feac7409c")));
    pool_index_map_.insert(std::make_pair(89, common::Encode::HexDecode("d91e88bb1dcefcf6f2336865c1b1d16637cf11da2bb9bd8abb912a00bd138109")));
    pool_index_map_.insert(std::make_pair(90, common::Encode::HexDecode("fc93494eb527cff5f591e16448800fb6cd5ff01a8ae7e1259e2b5269b32c5863")));
    pool_index_map_.insert(std::make_pair(91, common::Encode::HexDecode("430a2f5191aa827210ffc76ab1350b31bd4e0bdddd75883059f93a6a9b1f2aa2")));
    pool_index_map_.insert(std::make_pair(92, common::Encode::HexDecode("e8108e7243d09852972147bbc716d147160252924b02a94323e6696c142f876d")));
    pool_index_map_.insert(std::make_pair(93, common::Encode::HexDecode("1504e450380743153fc433a3472b086173343b04f2c3f91097777b59a0847a24")));
    pool_index_map_.insert(std::make_pair(94, common::Encode::HexDecode("0253859e7c1a6dd020366e92ec9e2128c33a0158483fd63b3731d1fc28df7c15")));
    pool_index_map_.insert(std::make_pair(95, common::Encode::HexDecode("a3db40f9ba93416d24d3535486187237d31093fc8d7fbd5e92a9b62fd44d2724")));
    pool_index_map_.insert(std::make_pair(96, common::Encode::HexDecode("e33dc73f2b58e682800c5606a0f89b677012f12d12ce7505c92821b81470221d")));
    pool_index_map_.insert(std::make_pair(97, common::Encode::HexDecode("85e2c8a587d3d73e21a062c6ff339d7d3eb2ede340cbff811b98761e183f9817")));
    pool_index_map_.insert(std::make_pair(98, common::Encode::HexDecode("e6bb25b85197da2b22695eca608ae1c4dcfee7838d04be00b8948d7bb291bd6a")));
    pool_index_map_.insert(std::make_pair(99, common::Encode::HexDecode("c246005594ee407e36db264aa0cbf02b6605ffba28d5b98dc67fc7693b440194")));
    pool_index_map_.insert(std::make_pair(100, common::Encode::HexDecode("97fc3fba6811210cc6cd81a1249c6077c6745ade2605e6f12e0bbf8ddd6c89df")));
    pool_index_map_.insert(std::make_pair(101, common::Encode::HexDecode("66fd6838471ba5f0e2d72858016984b50eb737d4a06df0c66a0a98f903514849")));
    pool_index_map_.insert(std::make_pair(102, common::Encode::HexDecode("68f99eeb447d17f87aca37083fb9425f4af07ad0ae0f5743dcc4602f718c8f9e")));
    pool_index_map_.insert(std::make_pair(103, common::Encode::HexDecode("74d8c3bf8163b7036491aaf1e41f4b669289f316482522f7ff99c1aa55ffd02b")));
    pool_index_map_.insert(std::make_pair(104, common::Encode::HexDecode("d8f54e15dd5987d8e2dac58b474652e54b9730a08beef72234fe4a33fe720925")));
    pool_index_map_.insert(std::make_pair(105, common::Encode::HexDecode("80000abe8755288323b85de48f8bc50089788b52aea8b61df8076c0a5722f94b")));
    pool_index_map_.insert(std::make_pair(106, common::Encode::HexDecode("724a9de201f7b76d9aab1cf636ae4d28556f59dfb6481a7b35527b2d8cdc7f5d")));
    pool_index_map_.insert(std::make_pair(107, common::Encode::HexDecode("b65b3ff9715cbda366c1483c465ae86b16f00830d71958408ee1ebcea8ebb7dd")));
    pool_index_map_.insert(std::make_pair(108, common::Encode::HexDecode("5463f1c874586cc0cdb70a16c8ad2daf899d045b5ad3285a51918d05cabb4aa6")));
    pool_index_map_.insert(std::make_pair(109, common::Encode::HexDecode("dfaf083e952944ae5b6fa448ff4eadbb02cb0ea8291a7fe3064978f3a0b19576")));
    pool_index_map_.insert(std::make_pair(110, common::Encode::HexDecode("158a18f4d1d042e575d6e7b83f6e1b770115d99e43365fcee554132607d6c516")));
    pool_index_map_.insert(std::make_pair(111, common::Encode::HexDecode("036d5818f9ab8baf01e83011ac97b02a2198643f19ffc8f7733c69695c5d0340")));
    pool_index_map_.insert(std::make_pair(112, common::Encode::HexDecode("eedf58390835384b79a629a0ff2319dce658a2996559890d0f1ec4252d534198")));
    pool_index_map_.insert(std::make_pair(113, common::Encode::HexDecode("c2d7c8bea1f7a15e77f89757bd10a9ebe68a6a1b29e215229036f65197c8d92e")));
    pool_index_map_.insert(std::make_pair(114, common::Encode::HexDecode("e87d911d97a5d81172adc1e28f282c532232fa2513a10076e5b4ed1f94f28423")));
    pool_index_map_.insert(std::make_pair(115, common::Encode::HexDecode("885390534f33d2f14a7d2a2c1583c1c7c37565f5f9eb5b627eb2ad32766f35ad")));
    pool_index_map_.insert(std::make_pair(116, common::Encode::HexDecode("72260ce1a71de2c693a9524c99244efba80dca27d0fe3880150eba5e828ece99")));
    pool_index_map_.insert(std::make_pair(117, common::Encode::HexDecode("3e85bb512d4f741524002b3665f889fe26f4711ccad89aaaf3835aba7c698349")));
    pool_index_map_.insert(std::make_pair(118, common::Encode::HexDecode("0d2d469af1d847d98bb9149d95f58d8258ce0640ba25c3fdc03b6ea80dbf57a5")));
    pool_index_map_.insert(std::make_pair(119, common::Encode::HexDecode("53d2b81cb2c422ea8edf0ba23c384e2ca81f38aaafac5eb6b811b9884ee4e770")));
    pool_index_map_.insert(std::make_pair(120, common::Encode::HexDecode("9d73fcf9b3af295f7fcbbf4cb7a1cfe97256143ec7c474bf32d95793a2716a8f")));
    pool_index_map_.insert(std::make_pair(121, common::Encode::HexDecode("37735951a18ea690c2ed8fe956369e9deb0059d4f223525dc2fb969c4188f7ec")));
    pool_index_map_.insert(std::make_pair(122, common::Encode::HexDecode("38736772447ccf01ca2929f625e7f17f99b3f94ca4744441f9884bacb5225246")));
    pool_index_map_.insert(std::make_pair(123, common::Encode::HexDecode("abd5c635db9cb9167a168e9e5c18a1c6212bd9b40040ce7a8daf00b3d425a49b")));
    pool_index_map_.insert(std::make_pair(124, common::Encode::HexDecode("a40344401f7986e1a705cd4ca47bd9e92e5fcdda89770c0bb9f601f549e0d0ca")));
    pool_index_map_.insert(std::make_pair(125, common::Encode::HexDecode("fca3b7227c4bb869c3568cfcbabb927be63cd616d6f22c3b7176380c7bb52ba9")));
    pool_index_map_.insert(std::make_pair(126, common::Encode::HexDecode("81a998d3de3de38c8580246cbeca088633f57b2525d588c59bae468cfa72df7a")));
    pool_index_map_.insert(std::make_pair(127, common::Encode::HexDecode("ee7da3be9b34cd6b172df76cdd0e355f4df2f4a9f6b8eae0f6690e3b1702b197")));
    pool_index_map_.insert(std::make_pair(128, common::Encode::HexDecode("1a7c79f547bcb468fa8e731075cf8a456be3c8777adcb1b94bce14191aac6134")));
    pool_index_map_.insert(std::make_pair(129, common::Encode::HexDecode("85e5b8766f26238c090d7ad31e1d1d86aa149cd529f85e5683ec675d0ffc4fb2")));
    pool_index_map_.insert(std::make_pair(130, common::Encode::HexDecode("61441daa24ffdb52f39ac04a89f34ec5b4e344d94a51338923c6ce3a5fe8dc33")));
    pool_index_map_.insert(std::make_pair(131, common::Encode::HexDecode("eb8ae816b1f6d1a13fc52ff806fe4e13a8d2a47902d80f5ce5feade375989d81")));
    pool_index_map_.insert(std::make_pair(132, common::Encode::HexDecode("97861a4b7fc024839154dc4f8c6174b47fbcb49a522b08f852beafd9e658a291")));
    pool_index_map_.insert(std::make_pair(133, common::Encode::HexDecode("c82aea6d06cef2854d82a1e43204439c45859d61d5f2aea590c2fbdc96780831")));
    pool_index_map_.insert(std::make_pair(134, common::Encode::HexDecode("679cce9ffe29a90a9fa9536cfc2f9436268caedcbbdb648ff6f3244db8cbc95f")));
    pool_index_map_.insert(std::make_pair(135, common::Encode::HexDecode("7441ce2997999ab7fbaf766098e990bb1cc34608145a0ec43f2eb1b1b17b17e0")));
    pool_index_map_.insert(std::make_pair(136, common::Encode::HexDecode("7da22092d42ca49662913355328c1de39ff6f86f5594d35f240159d466fe953c")));
    pool_index_map_.insert(std::make_pair(137, common::Encode::HexDecode("ffdc9a1e3d20574bd3ab010e276664325d35165334f6fe61cf28b117f106a8b6")));
    pool_index_map_.insert(std::make_pair(138, common::Encode::HexDecode("fdd45aabeccbcc4eb571c1dc2e0848b9456378b1a2e569fce73d5c733f0ac6ab")));
    pool_index_map_.insert(std::make_pair(139, common::Encode::HexDecode("0f412181a2fef578f54ee5592fa9ff05d8028214ff2eab063221d77522534aed")));
    pool_index_map_.insert(std::make_pair(140, common::Encode::HexDecode("60a7fd3840d138e595bd7820de0e2316ae1d9c68ce926ecb47d8a289b275c67d")));
    pool_index_map_.insert(std::make_pair(141, common::Encode::HexDecode("8fddb8bf8883acea4a25544d2d36b668e79383841dce6443d4312f32d646b134")));
    pool_index_map_.insert(std::make_pair(142, common::Encode::HexDecode("813365532ba268896ea763e79bf5b4656defd79c689313f5dcc651e358c76c90")));
    pool_index_map_.insert(std::make_pair(143, common::Encode::HexDecode("3d75c16ad44b019b6b32b088070daa2e8aa30c5834ee2ef3e4ffd5b0c16e44b7")));
    pool_index_map_.insert(std::make_pair(144, common::Encode::HexDecode("0baf8a943c1064d90e7cea36486595133733335accf6cbbc3bcfdc9b4c8cbc5c")));
    pool_index_map_.insert(std::make_pair(145, common::Encode::HexDecode("b44d52ec4bd55629c1f12daac55eaf559325847c1293444ac482f49de0602962")));
    pool_index_map_.insert(std::make_pair(146, common::Encode::HexDecode("a2b689e2cf31f92549b6e58bd91e9e353e7b6d0d3628c420ddb15db77cbe5af0")));
    pool_index_map_.insert(std::make_pair(147, common::Encode::HexDecode("513d00bc4ef7d4d62150d72e2e6123e09d28ccd94b8ef0b52b1efe9f786de8af")));
    pool_index_map_.insert(std::make_pair(148, common::Encode::HexDecode("143808af8f11855622236c2eb4e642ebfeca9d2d56956482ac7a66b064f700a5")));
    pool_index_map_.insert(std::make_pair(149, common::Encode::HexDecode("2ec96ac9249a6a5352233d0b45b51c7365d2e3f26879e78dd1ff55cd8075dfee")));
    pool_index_map_.insert(std::make_pair(150, common::Encode::HexDecode("279b0cba1a501d1355266c49d5aae0ecf2bfc8764d5c31f957590cae5b76f7f0")));
    pool_index_map_.insert(std::make_pair(151, common::Encode::HexDecode("d294bedb1c13707164a165225a98556a40bbf54284c41390a718741ce4ea2032")));
    pool_index_map_.insert(std::make_pair(152, common::Encode::HexDecode("994950518d285eb7c5db7c249f96cf9ccbd5aeaaff1e4c941a1f9669de283f42")));
    pool_index_map_.insert(std::make_pair(153, common::Encode::HexDecode("a0f1db120629264d11b8f1b9100aac38613b350b861b05c1898d4a87354493c7")));
    pool_index_map_.insert(std::make_pair(154, common::Encode::HexDecode("a22357972ca5eba6a3e3659c1b5e45b313605038c995d7fd514f3ee56ea8607b")));
    pool_index_map_.insert(std::make_pair(155, common::Encode::HexDecode("21d577560c26a5937f81916cd92a575ccbb9e595bf1e2ba001bf761b95d43dbe")));
    pool_index_map_.insert(std::make_pair(156, common::Encode::HexDecode("b37d6b568fb7f59e191c2e8171caf07959009a2423aeb37b4018d4061b1ce859")));
    pool_index_map_.insert(std::make_pair(157, common::Encode::HexDecode("9c2d5030f3e7ab4458f3fa122744f6c45cb460e19baa6725bb0c2ea2339924bd")));
    pool_index_map_.insert(std::make_pair(158, common::Encode::HexDecode("545f88234909a1018a2e54db40ed1742b7b566db5e534fd9c150140e3e3bf75e")));
    pool_index_map_.insert(std::make_pair(159, common::Encode::HexDecode("febe2365aafaa49d2438fa43016ce40eb7f26c35f19d5ff519c9116725c9a569")));
    pool_index_map_.insert(std::make_pair(160, common::Encode::HexDecode("73977d6cd1c25dd50700992890dcf37c535899e650af4ab74fcc16920cb3ab95")));
    pool_index_map_.insert(std::make_pair(161, common::Encode::HexDecode("1a7c23c582830f518168b999e334178a6df95bcb677790daa0ce1e1ea2c18002")));
    pool_index_map_.insert(std::make_pair(162, common::Encode::HexDecode("92903318b6f9920720cbd86794d1d04ac235b4ad9828990b3a62ad1ee91c7b")));
    pool_index_map_.insert(std::make_pair(163, common::Encode::HexDecode("138dbf625b5d2c2bf34e7ec87ab4656cb623079f47c934c010c364940774ffbf")));
    pool_index_map_.insert(std::make_pair(164, common::Encode::HexDecode("3af376f7ce97e6a17e477b5168d0e8d4e4b6f5085b0b0320ae0a33194a498d55")));
    pool_index_map_.insert(std::make_pair(165, common::Encode::HexDecode("06ebde365fea76a7b283ccfcd542a6616feebf8a527726edfeab040a75eb755e")));
    pool_index_map_.insert(std::make_pair(166, common::Encode::HexDecode("20ceb20557f76b32f1478772b6b338c1f470d521157a4717f794436c391befc8")));
    pool_index_map_.insert(std::make_pair(167, common::Encode::HexDecode("9a6319cfbe1ac36a62e2515f1e7c92354bd4371af523a8c71e5c22674aaf54d9")));
    pool_index_map_.insert(std::make_pair(168, common::Encode::HexDecode("98e90f36e6ddd00add84a83444666dae474b2cca938cb274f513583960145ed2")));
    pool_index_map_.insert(std::make_pair(169, common::Encode::HexDecode("9385a502948ece346ea41b0dec22c39cb2132443bd0aad5ff9e0aa9546542a81")));
    pool_index_map_.insert(std::make_pair(170, common::Encode::HexDecode("863bb5c519bdae744cb2dc36ea7e1c81536e2f307476f4b2a1409766c17323b1")));
    pool_index_map_.insert(std::make_pair(171, common::Encode::HexDecode("08006141f5817ee2c4ca969a579a5241368dcb1c60e02fe2322787bc82bebc95")));
    pool_index_map_.insert(std::make_pair(172, common::Encode::HexDecode("92cbad3a7d76ede7f34f872b25bd3a80db746b6b5d9e9499e7895c1af1d2e3a0")));
    pool_index_map_.insert(std::make_pair(173, common::Encode::HexDecode("324fc6842e4d3686a28bf690ad770db64ed983dd7484e1a43b36469f2d721e12")));
    pool_index_map_.insert(std::make_pair(174, common::Encode::HexDecode("d54167effbdfccb85aebd03870a8cb29a1f68524d8c555bc176a949c46d097a4")));
    pool_index_map_.insert(std::make_pair(175, common::Encode::HexDecode("2f1019a2ec8300dbf5668a71b5b230fdf8008de2a323b3c4a505ac0c833ab8fc")));
    pool_index_map_.insert(std::make_pair(176, common::Encode::HexDecode("4ebb8ebb08e865a8e25876f98c99c8f21650cca266c8554139e0d8c4aff565ed")));
    pool_index_map_.insert(std::make_pair(177, common::Encode::HexDecode("5d5b80d1c0cfcec39ffb9a181c261ea77cf7acc3eacf5eaa4c78bb75048e2168")));
    pool_index_map_.insert(std::make_pair(178, common::Encode::HexDecode("9be80bad838a62f9eb6fc9598abdcb63c0c7340b975d50e3f76bca2de6114f17")));
    pool_index_map_.insert(std::make_pair(179, common::Encode::HexDecode("e9b60b37544cfae4581fde9682628e4de1f6b490337e60b4be20429310c91148")));
    pool_index_map_.insert(std::make_pair(180, common::Encode::HexDecode("310098a85310400c43c6757f1530c7fa199c241b8b4043343c927b57f9a1fce8")));
    pool_index_map_.insert(std::make_pair(181, common::Encode::HexDecode("e27bcc23b06a201c8a5b947b57f9ddd0791d61b42dda109c34ca11c7c3096c73")));
    pool_index_map_.insert(std::make_pair(182, common::Encode::HexDecode("c5c482422be0f907b368ac52015701a88dc17fb5d7b35ada02e3922d6358ba34")));
    pool_index_map_.insert(std::make_pair(183, common::Encode::HexDecode("caecf015a460846cf31de81215d76b1f72c3517daeaf00a51cb3f28a3d83cd08")));
    pool_index_map_.insert(std::make_pair(184, common::Encode::HexDecode("fcf882211eccf860b2579ac72fe344ba6cf221b432acd9648f31419e6472aa18")));
    pool_index_map_.insert(std::make_pair(185, common::Encode::HexDecode("d0d65302df20abe7cb4d9abe48b30cc931d3535a602ef197e32386cd67ed3265")));
    pool_index_map_.insert(std::make_pair(186, common::Encode::HexDecode("c4cd1edbd47b4243e2d1aab1cb2eda7a59cbd44f472e185585ec9a6409b2b4d4")));
    pool_index_map_.insert(std::make_pair(187, common::Encode::HexDecode("b34b5a2c9e76082b74e1df363404ff0e6e218490327ef6e5f0e1cf09c8b55b53")));
    pool_index_map_.insert(std::make_pair(188, common::Encode::HexDecode("6e834c496a19258235e85046dd5b78244285e6b92712ca22255a9dfc7e64a773")));
    pool_index_map_.insert(std::make_pair(189, common::Encode::HexDecode("215f4413bcfa964e740b44394498681efef411cd84977bf24a19623e6f0bb6c3")));
    pool_index_map_.insert(std::make_pair(190, common::Encode::HexDecode("f954af36f01e17b474e7d1df0f3e27bde3b60bf3ac8379dc4ee25c65139fdc91")));
    pool_index_map_.insert(std::make_pair(191, common::Encode::HexDecode("4b7a6af4ba9b2bd4e0e3028b8e4ac7aa4d2a6a6dd3d2da9ec1a7d102d7d29902")));
    pool_index_map_.insert(std::make_pair(192, common::Encode::HexDecode("2a5410c202e2166818a2a4a089e3b521dba647130849a81332f26ed533db68c1")));
    pool_index_map_.insert(std::make_pair(193, common::Encode::HexDecode("41e1e34b07b5bb071fb301ffcee5dadc6fb280e2c66e4e4adb864ca1d1571833")));
    pool_index_map_.insert(std::make_pair(194, common::Encode::HexDecode("a2e97e96d3f817b3157844a122db327dcefd7db15e7671b53395e8c5d736c9ad")));
    pool_index_map_.insert(std::make_pair(195, common::Encode::HexDecode("b4b8be050186c44d60379544af23e00beba3562e51a9d8be9f3c88614428ce2b")));
    pool_index_map_.insert(std::make_pair(196, common::Encode::HexDecode("078c33f6546fc8697a26c9b723b48ed2e4663d8b9b9a106284993b44ad7702")));
    pool_index_map_.insert(std::make_pair(197, common::Encode::HexDecode("ac714ba23774cc7c7349d6fa058bff44393c8d3ee894d4cf0269f239b4df3abe")));
    pool_index_map_.insert(std::make_pair(198, common::Encode::HexDecode("39dfcb499d2b7ef023ed1b41f7c038c7348adaae0e62fb87f11ea99effa3952e")));
    pool_index_map_.insert(std::make_pair(199, common::Encode::HexDecode("373ca30989c70464fa1bf2bd67a80f04284036797d61ddb9a11f73de03038446")));
    pool_index_map_.insert(std::make_pair(200, common::Encode::HexDecode("8fba5296be5ffb962eca11ef09ca6265cc15760af5d440f1a25b1b611138b298")));
    pool_index_map_.insert(std::make_pair(201, common::Encode::HexDecode("798c886bf4eed0d1f6e755d267a605cdbd6d454b5569c93c06b34dcd20d3fc7a")));
    pool_index_map_.insert(std::make_pair(202, common::Encode::HexDecode("ec46547d4d21b913b0b6d4a9ba02d7b851fb4bdb5e75540793a47719739bd78e")));
    pool_index_map_.insert(std::make_pair(203, common::Encode::HexDecode("426cd01e536ceaf6aec6b352a85f600d89ef3aa5bf1a9b7dea855d88c9f12b48")));
    pool_index_map_.insert(std::make_pair(204, common::Encode::HexDecode("83e9dd1d69dd98afc0289f77e33215d4375f610acd0db7f6ff0925582b190889")));
    pool_index_map_.insert(std::make_pair(205, common::Encode::HexDecode("f7f1efb1a6f0ec3f49ee9008438ec2136f0d7b7d51d75bc55d559cfeb1fd7011")));
    pool_index_map_.insert(std::make_pair(206, common::Encode::HexDecode("bd2fca7e16cfd583fee1dc8fc3b69c31dba2aa7211afc9a2d5715418d05eb016")));
    pool_index_map_.insert(std::make_pair(207, common::Encode::HexDecode("a6e9c165eb534dea311b99eae8fae381fb5af57ed8dd474cb9c4e502854016e5")));
    pool_index_map_.insert(std::make_pair(208, common::Encode::HexDecode("4b43c014c31b2ca1b488524ddb2de60c5d8992472331944bc53f27afa76b6512")));
    pool_index_map_.insert(std::make_pair(209, common::Encode::HexDecode("42f8077de021eb3baae428ece6292b0c5e8b7779c17d2367def012a347520c64")));
    pool_index_map_.insert(std::make_pair(210, common::Encode::HexDecode("9e23b14d06377a9ede9aac98f16d495c87b03264def0880c63ba5cb146f9473f")));
    pool_index_map_.insert(std::make_pair(211, common::Encode::HexDecode("c7787479aeeaab19646441c006443da65388a6355c3a21e3dc48049ad6449661")));
    pool_index_map_.insert(std::make_pair(212, common::Encode::HexDecode("db308c27344fae69382ebf6d216e18371a2c146651773cc67b14b770ba1a1d9d")));
    pool_index_map_.insert(std::make_pair(213, common::Encode::HexDecode("313e94817afe6985fa4eab4d5ab45abe2a96364f4baad43c8aa6a6f441a47a20")));
    pool_index_map_.insert(std::make_pair(214, common::Encode::HexDecode("544639d6a3208469bc3aae02acd1b6c73d7be0656b1be85fd402f2b2e49660a2")));
    pool_index_map_.insert(std::make_pair(215, common::Encode::HexDecode("d920990b509acac6d7313d056dd9340de502b4b7a784fd3015920a980cb8aa90")));
    pool_index_map_.insert(std::make_pair(216, common::Encode::HexDecode("7dae638a668029587e7e170ef0e562b5f60a2ef8e43dc859d334ac154a50257a")));
    pool_index_map_.insert(std::make_pair(217, common::Encode::HexDecode("a35db59292e6aa6beac6e08ef34abf685e46a250bb31e94cc73b2d232d4497c5")));
    pool_index_map_.insert(std::make_pair(218, common::Encode::HexDecode("2cedc1724db3021ddf9f6a0dca36f2374a2078dc3be29b5dde470f959bd065fd")));
    pool_index_map_.insert(std::make_pair(219, common::Encode::HexDecode("a65d28921e67976ccfab6acfa71092c79a9b61e93155a1bc75849855aa02153a")));
    pool_index_map_.insert(std::make_pair(220, common::Encode::HexDecode("d3444f6e874f17bfcdbcc3a74553de18b648a461030d20655fcea5e7be604b1a")));
    pool_index_map_.insert(std::make_pair(221, common::Encode::HexDecode("547c5c66cbfcf1d17536173502ba574eed63d59aa90a6c06e96fc472610f2d66")));
    pool_index_map_.insert(std::make_pair(222, common::Encode::HexDecode("a0731d785680ff831bc9e428b4a01e4f58db1fc569d4b14f6d66d4869ed9f864")));
    pool_index_map_.insert(std::make_pair(223, common::Encode::HexDecode("adaa675f8a0b82c40b75d0108ca7b4cfa0739da266adee143c1371402f646a9a")));
    pool_index_map_.insert(std::make_pair(224, common::Encode::HexDecode("ef0d28b87c6b686f0f1e0c2a0a6f7026a69d220374edfe389b2cce9b399b215c")));
    pool_index_map_.insert(std::make_pair(225, common::Encode::HexDecode("fd8f498cb2ded6a3050630dfa641b190b76ce59b4c25608c6d5b505ddea4827c")));
    pool_index_map_.insert(std::make_pair(226, common::Encode::HexDecode("1db3b65e3cff12be6964d8135b22022d08340fa7464eb88eae2bf39489d6efa0")));
    pool_index_map_.insert(std::make_pair(227, common::Encode::HexDecode("abee33fa20cb1f305016b9e1cfa8a3864c5a3436f55048bb3ce8c9c45cd08004")));
    pool_index_map_.insert(std::make_pair(228, common::Encode::HexDecode("365e11141936e2b7ae6bbca12ddcf0b6a83792ce146f36974a07d0b5d1f3d0dc")));
    pool_index_map_.insert(std::make_pair(229, common::Encode::HexDecode("ae8754bf5c7a8fecf4b80335d9ff85011dab7df260b62314a14e8c58c150273a")));
    pool_index_map_.insert(std::make_pair(230, common::Encode::HexDecode("f8e9a348250f15d5712ef3d1d55bbd1c0814ec9fc50e83ab1a288d22c5587e38")));
    pool_index_map_.insert(std::make_pair(231, common::Encode::HexDecode("b8dc4c1993541392ea8549dcc712c84b360a99efe5829cb8b27ec7070bf0ae8b")));
    pool_index_map_.insert(std::make_pair(232, common::Encode::HexDecode("dabdad072eb44afa69899bcc705df1cfe0eb77934c46063ac3d53b84a67f0404")));
    pool_index_map_.insert(std::make_pair(233, common::Encode::HexDecode("c0d2ec3a99b4c12fa400867da1ef325b1d9942691141e9bfde92138bddce594b")));
    pool_index_map_.insert(std::make_pair(234, common::Encode::HexDecode("f452d1de193124b55cf2d88155d119b67f3baf520cb7e46e4b02651ed8a3267a")));
    pool_index_map_.insert(std::make_pair(235, common::Encode::HexDecode("c312bdaf10e31a468f2c4f3677709aab714d6b0a86bc6d27cd2b9814d6c992ef")));
    pool_index_map_.insert(std::make_pair(236, common::Encode::HexDecode("1b21ec3b839640645bee5016e4acfb3935df43c1966b39ce12a6f2e37c0bebb7")));
    pool_index_map_.insert(std::make_pair(237, common::Encode::HexDecode("45c5ae1a622c72e9957172580eb4b18ca66416587345471c3234aa51942b573b")));
    pool_index_map_.insert(std::make_pair(238, common::Encode::HexDecode("440ae9c43cd74746d3a9171443dc0143ae7b8a5bb68918670e3b8e342db76132")));
    pool_index_map_.insert(std::make_pair(239, common::Encode::HexDecode("dcdff53a53cc70c03b85fd04b36e5a449d5a84890a77323325ca9464687fe14c")));
    pool_index_map_.insert(std::make_pair(240, common::Encode::HexDecode("341e9505c64c990242b920e3adf77634ff815d38056fe7ddc5c1114976902e78")));
    pool_index_map_.insert(std::make_pair(241, common::Encode::HexDecode("9436da3c8d423767e60963979104f2e640920c68d1fda99ceeefbd87917e0092")));
    pool_index_map_.insert(std::make_pair(242, common::Encode::HexDecode("e1fa6eea9be8dfced6b04bc8816f0616d7630071c8abfb944dffa53f7762b05b")));
    pool_index_map_.insert(std::make_pair(243, common::Encode::HexDecode("82f5bd0507d47d5e96a79d6dfdd70e3daf69fd8d361cb9c9799f115ef7d95966")));
    pool_index_map_.insert(std::make_pair(244, common::Encode::HexDecode("23bcbe0d3e6a35ce081c53e4b7f5a039f4ab054cca7abe5ac040968fd1c5ce58")));
    pool_index_map_.insert(std::make_pair(245, common::Encode::HexDecode("f229a4b0ec84327b90cf479767dc5781ec69c3bc207f97e45194340e9215260e")));
    pool_index_map_.insert(std::make_pair(246, common::Encode::HexDecode("c8cc29f590cbe30bea1a9999b740868460efe2c378a448811d5993f9cdb74fc1")));
    pool_index_map_.insert(std::make_pair(247, common::Encode::HexDecode("73d8d1e0dab820c72cc0e2e254ef96624fde373fd39bf6787e7261390f724e54")));
    pool_index_map_.insert(std::make_pair(248, common::Encode::HexDecode("b46c6cbbdb407daf7d1611f9ee416306c5c6098dfc83fe80d0fc8ff7a744a134")));
    pool_index_map_.insert(std::make_pair(249, common::Encode::HexDecode("78b7c1e4c571463ef72e70ef478f8534c5de576ce80f94a924807fcf3f9ac397")));
    pool_index_map_.insert(std::make_pair(250, common::Encode::HexDecode("6b41438696ebb429edf3aaf8ad907ad0696605f64acd9401115f4067d1737cd5")));
    pool_index_map_.insert(std::make_pair(251, common::Encode::HexDecode("2e3463eda6fb40355942e16d67c867392e6184171e14aed073aa68b4d36d7825")));
    pool_index_map_.insert(std::make_pair(252, common::Encode::HexDecode("81b6502516f876206e562bdefb8d7d1507b0bccffdc0f61c1b34ccf0bfd208c7")));
    pool_index_map_.insert(std::make_pair(253, common::Encode::HexDecode("3db21474a70303482c8c8c4395ff4c97120b69832bef162b21675ea5422627fc")));
    pool_index_map_.insert(std::make_pair(254, common::Encode::HexDecode("9dde2eaab26334ff348959a02bcebedee37de577792b82992e90f0a8136347ae")));
    pool_index_map_.insert(std::make_pair(255, common::Encode::HexDecode("593bee91f956047f7dfa1df3603dfdb701b5e5fb601e4836a00ebd7a65f48d4d")));

    for (auto iter = pool_index_map_.begin(); iter != pool_index_map_.end(); ++iter) {
        std::cout << "pool_index_map_.insert(std::make_pair(" << iter->first << ", common::Encode::HexDecode(\"" << common::Encode::HexEncode(security::Secp256k1::Instance()->ToAddressWithPrivateKey(iter->second)) << "\")));" << std::endl;
    }
}

};  // namespace init

};  // namespace tenon
