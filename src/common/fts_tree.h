#pragma once

#include <cmath>
#include <vector>
#include <random>
#include <set>

#include "common/utils.h"

namespace tenon {

namespace common {

struct FtsNode {
    uint64_t fts_value;
    uint32_t parent;
    uint32_t left;
    uint32_t right;
    void* data;
};

class FtsTree {
public:
    FtsTree();
    ~FtsTree();
    void AppendFtsNode(uint64_t fts_value, void* data);
    void CreateFtsTree();
    void GetNodes(uint64_t init_rand_num, uint32_t count, std::set<void*>& nodes);

private:
    void* GetOneNode(std::mt19937_64& g2);

    std::vector<FtsNode> fts_nodes_;
    uint32_t root_node_index_{ 0 };
    uint32_t base_node_index_{ 0 };
};

};  // namespace common

};  // namespace tenon
