#include "stdafx.h"
#include "common/global_info.h"

#include "uuid/uuid.h"
#include "common/random.h"
#include "common/hash.h"
#include "common/country_code.h"
#include "common/log.h"
#include "common/encode.h"

namespace tenon {

namespace common {

static const std::string kAccountAddress("");

GlobalInfo* GlobalInfo::Instance() {
    static GlobalInfo ins;
    return &ins;
}

GlobalInfo::GlobalInfo()
		: id_(kAccountAddress),
	      message_id_(TimeStampMsec()),
	      network_id_(kDefaultTestNetworkShardId) {
    id_string_hash_ = Hash::Hash192(id_);
    id_hash_ = Hash::Hash64(id_);
    gid_hash_ = Hash::Sha256(Random::RandomString(4096u));

    vpn_minning_accounts_.insert(common::Encode::HexDecode("dc161d9ab9cd5a031d6c5de29c26247b6fde6eb36ed3963c446c1a993a088262"));
    vpn_minning_accounts_.insert(common::Encode::HexDecode("5595b040cdd20984a3ad3805e07bad73d7bf2c31e4dc4b0a34bc781f53c3dff7"));
    vpn_minning_accounts_.insert(common::Encode::HexDecode("25530e0f5a561f759a8eb8c2aeba957303a8bb53a54da913ca25e6aa00d4c365"));
    vpn_minning_accounts_.insert(common::Encode::HexDecode("9eb2f3bd5a78a1e7275142d2eaef31e90eae47908de356781c98771ef1a90cd2"));
    vpn_minning_accounts_.insert(common::Encode::HexDecode("c110df93b305ce23057590229b5dd2f966620acd50ad155d213b4c9db83c1f36"));

    vpn_committee_accounts_.insert(common::Encode::HexDecode("f64e0d4feebb5283e79a1dfee640a276420a08ce6a8fbef5572e616e24c2cf18"));
    vpn_committee_accounts_.insert(common::Encode::HexDecode("7ff017f63dc70770fcfe7b336c979c7fc6164e9653f32879e55fcead90ddf13f"));
    vpn_committee_accounts_.insert(common::Encode::HexDecode("6dce73798afdbaac6b94b79014b15dcc6806cb693cf403098d8819ac362fa237"));
    vpn_committee_accounts_.insert(common::Encode::HexDecode("b5be6f0090e4f5d40458258ed9adf843324c0327145c48b55091f33673d2d5a4"));

//     vpn_committee_accounts_.insert(common::Encode::HexDecode("bf5ca772cbb45bebbd2d420275ca1d9988d8ce36f267b21835248365552d382a"));
//     vpn_committee_accounts_.insert(common::Encode::HexDecode("e6b0b4c681d2e6e563fd79871a361f30509bb08aa51904b64a02641cf0c7c543"));
//     vpn_committee_accounts_.insert(common::Encode::HexDecode("8b66b670a51835e52371991927b6623a94ac7924c7649194f700ad4f7dbe06d5"));
//     vpn_committee_accounts_.insert(common::Encode::HexDecode("335b0be5b571c3614547247c52dda18d71371397214d0030cd759af9dadcf705"));
//     vpn_committee_accounts_.insert(common::Encode::HexDecode("536047225823244a10f96d2ff226d2581cf996079ab6e1a01bfc33530ac0940c"));

    share_reward_accounts_.insert(common::Encode::HexDecode("044c345f1d1229dded31f979113b68b98ae5c06934997617db88a13a0d6f8974"));

    watch_ad_reward_accounts_.insert(common::Encode::HexDecode("4e26a976ce34f6d8b1675eb20880f2ec2459211be9c3915c833fb18680259ce3"));
    watch_ad_reward_accounts_.insert(common::Encode::HexDecode("20301be3f836b2b859c990920edd8d811ca5f0f592e1d4f1fcf39a22cd757b49"));
    watch_ad_reward_accounts_.insert(common::Encode::HexDecode("42601c5363b6214169141cc26f4bc2550c22dac7ca1bbc176a90291e8a6bb3be"));
}

GlobalInfo::~GlobalInfo() {}

int GlobalInfo::Init(const common::Config& config) {
    if (!config.Get("tenon", "local_ip", config_local_ip_)) {
        TENON_ERROR("get tenon local_ip from config failed.");
        return kCommonError;
    }

    if (!config.Get("tenon", "local_port", config_local_port_)) {
        TENON_ERROR("get tenon local_port from config failed.");
        return kCommonError;
    }

    if (!config.Get("tenon", "http_port", http_port_)) {
        http_port_ = 0;
    }

    config.Get("tenon", "tcp_spec", tcp_spec_);
    std::string str_contry;
    if (!config.Get("tenon", "country", str_contry) || str_contry.empty()) {
        TENON_ERROR("get tenon country from config failed.");
        return kCommonError;
    }
    country_ = global_country_map[str_contry];

    if (!config.Get("tenon", "first_node", config_first_node_)) {
        TENON_ERROR("get tenon first_node from config failed.");
        return kCommonError;
    }

    std::string account_id;
    if (!config.Get("tenon", "id", account_id) || account_id.empty()) {
        TENON_ERROR("get tenon id from config failed.");
        return kCommonError;
    }
    set_id(account_id);

    config.Get("tenon", "stream_limit", stream_default_limit_);

    min_route_port_ = common::kVpnRoutePortRangeMin;
    max_route_port_ = common::kVpnRoutePortRangeMax;
    config.Get("tenon", "route_min_port", min_route_port_);
    config.Get("tenon", "route_max_port", max_route_port_);

    min_svr_port_ = common::kVpnServerPortRangeMin;
    max_svr_port_ = common::kVpnServerPortRangeMax;
    config.Get("tenon", "vpn_min_port", min_svr_port_);
    config.Get("tenon", "vpn_max_port", max_svr_port_);

    min_udp_port_ = common::kRouteUdpPortRangeMin;
    max_udp_port_ = common::kRouteUdpPortRangeMax;
    config.Get("tenon", "min_udp_port", min_udp_port_);
    config.Get("tenon", "max_udp_port", max_udp_port_);

    config.Get("tenon", "public_port", config_public_port_);
    config.Get("tenon", "node_weight", node_weight_);
    config.Get("tenon", "is_vlan_node", is_vlan_node_);
    config.Get("tenon", "is_lego_leader", is_lego_leader_);
    config.Get("tenon", "client", is_client_);
    config.Get("tenon", "node_tag", node_tag_);
    if (config.Get("tenon", "udp_mtu", udp_mtu_) && udp_mtu_ > 1400) {
        udp_mtu_ -= 100;  // reserve 100 bytes for package header and udp header
    }
    config.Get("tenon", "udp_window_size", udp_window_size_);

    return kCommonSuccess;
}

}  // namespace common

}  // namespace tenon
