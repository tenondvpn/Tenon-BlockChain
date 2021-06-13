#include "stdafx.h"
#include "root/root_init.h"

#include "common/global_info.h"
#include "election/elect_manager.h"

namespace tenon {

namespace root {

RootInit::RootInit() {}

RootInit::~RootInit() {}

int RootInit::Init() {
	congress_node_ = std::make_shared<RootNode>(
        network::kRootCongressNetworkId,
        std::bind(
            &elect::ElectManager::GetMemberWithId,
            elect::ElectManager::Instance(),
            std::placeholders::_1,
            std::placeholders::_2));
	if (congress_node_->Init() != network::kNetworkSuccess) {
		congress_node_ = nullptr;
		ROOT_ERROR("node join network [%u] failed!", network::kRootCongressNetworkId);
		return kRootError;
	}

	common::GlobalInfo::Instance()->set_network_id(network::kRootCongressNetworkId);
	return kRootSuccess;
}

}  // namespace root

}  // namespace tenon
