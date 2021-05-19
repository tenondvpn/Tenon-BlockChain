#include "stdafx.h"
#include "root_congress/congress_dht.h"

namespace tenon {

namespace congress {

CongressDht::CongressDht(transport::TransportPtr& transport, dht::NodePtr& local_node)
		: BaseDht(transport, local_node) {}

CongressDht::~CongressDht() {}

}  // namespace congress

}  // namespace tenon
