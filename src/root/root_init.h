#pragma once

#include "network/shard_network.h"
#include "root/root_utils.h"
#include "root/root_dht.h"

namespace tenon {

namespace root {

typedef network::ShardNetwork<RootDht> RootNode;
typedef std::shared_ptr<RootNode> CongressNodePtr;

class RootInit {
public:
	RootInit();
	~RootInit();
	int Init();

private:
	CongressNodePtr congress_node_{ nullptr };

	DISALLOW_COPY_AND_ASSIGN(RootInit);
};

}  // namespace root

}  // namespace tenon
