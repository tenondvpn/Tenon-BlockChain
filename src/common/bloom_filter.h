#pragma once

#include <cstdint>
#include <vector>
#include <cassert>
#include <string>

namespace tenon {

namespace common {

class BloomFilter {
public:
    BloomFilter() {}
    BloomFilter(uint32_t bit_count, uint32_t hash_count);
    BloomFilter(const std::vector<uint64_t>& data, uint32_t hash_count);
    ~BloomFilter();
    void Add(uint64_t hash);
    bool Contain(uint64_t hash);
    uint32_t DiffCount(const BloomFilter& other);
    BloomFilter& operator=(const BloomFilter& src);
    bool operator==(const BloomFilter& r) const;
    bool operator!=(const BloomFilter& r) const;

    const std::vector<uint64_t>& data() const {
        return data_;
    }

    uint32_t hash_count() {
        return hash_count_;
    }

    uint32_t valid_count() {
        return valid_count_;
    }

    std::string Serialize() {
        assert(!data_.empty());
        uint64_t* data = new uint64_t[data_.size()];
        for (uint32_t i = 0; i < data_.size(); ++i) {
            data[i] = data_[i];
        }

        std::string res((char*)data, data_.size() * sizeof(data[0]));
        delete[] data;
        return res;
    }

    void Deserialize(const uint64_t* data, uint32_t count, uint32_t hash_count);

private:
    std::vector<uint64_t> data_;
    uint32_t hash_count_{ 0 };
    uint32_t valid_count_{ 0 };
};

}  // namespace common

}  // namespace tenon
