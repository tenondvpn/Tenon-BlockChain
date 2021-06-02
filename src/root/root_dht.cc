#include "stdafx.h"
#include "root/root_dht.h"

namespace tenon {

namespace root {

RootDht::RootDht(transport::TransportPtr& transport, dht::NodePtr& local_node)
		: BaseDht(transport, local_node) {}

RootDht::~RootDht() {}

}  // namespace root

}  // namespace tenon
