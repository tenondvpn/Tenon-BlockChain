#include "common/fts_tree.h"

#include <cassert>

#include "common/random.h"

namespace tenon {

namespace common {

FtsTree::FtsTree() {}

FtsTree::~FtsTree() {}

void FtsTree::AppendFtsNode(uint64_t fts_value, void* data) {
    fts_nodes_.push_back({ fts_value, 0, 0, 0, data });
}

void FtsTree::CreateFtsTree() {
    if (fts_nodes_.empty()) {
        return;
    }

    uint32_t base_count = log2(fts_nodes_.size());
    base_node_index_ = (uint32_t)(pow(2.0, (float)base_count));
    if (base_node_index_ < fts_nodes_.size()) {
        base_count += 1;
        base_node_index_ = (uint32_t)(pow(2.0, (float)base_count));
    }

    uint32_t valid_nodes_size = fts_nodes_.size();
    for (uint32_t i = valid_nodes_size; i < base_node_index_; ++i) {
        fts_nodes_.push_back({ 0, 0, 0, 0, nullptr });
    }

    root_node_index_ = (uint32_t)pow(2.0f, (float)(base_count + 1)) - 2;
    for (uint32_t i = 0; ; ++i) {
        fts_nodes_[i].parent = i / 2 + (uint32_t)pow(2.0f, (float)(base_count));
        if (i % 2 != 0) {
            continue;
        }

        if (i == root_node_index_) {
            break;
        }

        auto sum_val = fts_nodes_[i].fts_value + fts_nodes_[i + 1].fts_value;
        fts_nodes_.push_back({
            sum_val,
            0,
            i,
            i + 1,
            nullptr });
    }
}

void FtsTree::GetNodes(uint64_t init_rand_num, uint32_t count, std::set<void*>& nodes) {
    if (fts_nodes_.empty()) {
        return;
    }

    if (count > nodes.size() / 3) {
        assert(false);
        return;
    }

    std::mt19937_64 g2(init_rand_num);
    while (nodes.size() < count) {
        nodes.insert(GetOneNode(g2));
    }
}

void* FtsTree::GetOneNode(std::mt19937_64& g2) {
    assert(fts_nodes_.size() == root_node_index_ + 1);
    uint32_t choose_idx = root_node_index_;
    while (true) {
        auto rand_value = g2() % fts_nodes_[choose_idx].fts_value;
        if (fts_nodes_[fts_nodes_[choose_idx].left].fts_value >
                fts_nodes_[fts_nodes_[choose_idx].right].fts_value) {
            if (rand_value < fts_nodes_[fts_nodes_[choose_idx].right].fts_value) {
                choose_idx = fts_nodes_[choose_idx].right;
            } else {
                choose_idx = fts_nodes_[choose_idx].left;
            }
        } else {
            if (rand_value < fts_nodes_[fts_nodes_[choose_idx].left].fts_value) {
                choose_idx = fts_nodes_[choose_idx].left;
            } else {
                choose_idx = fts_nodes_[choose_idx].right;
            }
        }

        if (choose_idx < base_node_index_) {
            return fts_nodes_[choose_idx].data;
        }
    }

    return nullptr;
}

};  // namespace common

};  // namespace tenon