#pragma once

#include "dht/base_dht.h"
#include "root/root_utils.h"

namespace tenon {

namespace root {

class RootDht : public dht::BaseDht {
public:
	RootDht(transport::TransportPtr& transport, dht::NodePtr& local_node);
	virtual ~RootDht();

private:

	DISALLOW_COPY_AND_ASSIGN(RootDht);
};

}  // namespace root

}  // namespace tenon
