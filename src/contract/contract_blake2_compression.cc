#include "contract/contract_blake2_compression.h"

#include "security/secp256k1.h"

namespace tenon {

namespace contract {

constexpr size_t BLAKE2B_BLOCKBYTES = 128;

struct blake2b_state
{
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
    uint8_t last_node;
};

// clang-format off
constexpr uint64_t blake2b_IV[8] =
{
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

constexpr uint8_t blake2b_sigma[12][16] =
{
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};
// clang-format on

inline uint64_t load64(const void* src) noexcept
{
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

inline constexpr uint64_t rotr64(uint64_t w, unsigned c) noexcept
{
    return (w >> c) | (w << (64 - c));
}

inline void G(uint8_t r, uint8_t i, uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d,
    const uint64_t* m) noexcept
{
    a = a + b + m[blake2b_sigma[r][2 * i + 0]];
    d = rotr64(d ^ a, 32);
    c = c + d;
    b = rotr64(b ^ c, 24);
    a = a + b + m[blake2b_sigma[r][2 * i + 1]];
    d = rotr64(d ^ a, 16);
    c = c + d;
    b = rotr64(b ^ c, 63);
}

inline void ROUND(uint32_t round, uint64_t* v, const uint64_t* m) noexcept
{
    uint8_t const r = round % 10;
    G(r, 0, v[0], v[4], v[8], v[12], m);
    G(r, 1, v[1], v[5], v[9], v[13], m);
    G(r, 2, v[2], v[6], v[10], v[14], m);
    G(r, 3, v[3], v[7], v[11], v[15], m);
    G(r, 4, v[0], v[5], v[10], v[15], m);
    G(r, 5, v[1], v[6], v[11], v[12], m);
    G(r, 6, v[2], v[7], v[8], v[13], m);
    G(r, 7, v[3], v[4], v[9], v[14], m);
}


void blake2b_compress(
    uint32_t rounds, blake2b_state* S, const uint8_t block[BLAKE2B_BLOCKBYTES]) noexcept
{
    uint64_t m[16];
    uint64_t v[16];

    for (size_t i = 0; i < 16; ++i)
        m[i] = load64(block + i * sizeof(m[i]));

    for (size_t i = 0; i < 8; ++i)
        v[i] = S->h[i];

    v[8] = blake2b_IV[0];
    v[9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    for (uint32_t r = 0; r < rounds; ++r)
        ROUND(r, v, m);

    for (size_t i = 0; i < 8; ++i)
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}


std::string blake2FCompression(
        uint32_t _rounds,
        const std::string& _stateVector,
        const std::string& _t0,
        const std::string& _t1,
        bool _lastBlock,
        const std::string& _messageBlockVector) {
    if (_stateVector.size() != sizeof(blake2b_state::h)) {
        assert(false);
        return "";
    }

    blake2b_state s{};
    std::memcpy(&s.h, _stateVector.data(), _stateVector.size());
    if (_t0.size() != sizeof(s.t[0]) || _t1.size() != sizeof(s.t[1])) {
        assert(false);
        return "";
    }

    s.t[0] = load64(_t0.data());
    s.t[1] = load64(_t1.data());
    s.f[0] = _lastBlock ? std::numeric_limits<uint64_t>::max() : 0;
    if (_messageBlockVector.size() != BLAKE2B_BLOCKBYTES) {
        assert(false);
        return "";
    }

    uint8_t block[BLAKE2B_BLOCKBYTES];
    std::copy(_messageBlockVector.begin(), _messageBlockVector.end(), &block[0]);
    blake2b_compress(_rounds, &s, block);
    return std::string((char*)&s.h[0], sizeof(s.h));
}

Blake2Compression::Blake2Compression(const std::string& create_address)
        : ContractInterface(create_address) {}

Blake2Compression::~Blake2Compression() {}

int Blake2Compression::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info,
        db::DbWriteBach& db_batch) {
    return kContractSuccess;
}

int Blake2Compression::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int Blake2Compression::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

int Blake2Compression::call(
        const CallParameters& param,
        uint64_t gas,
        const std::string& origin_address,
        evmc_result* res) {
    if (param.data.empty()) {
        return kContractError;
    }

    uint64_t gas_used = bignum::FromBigEndian<uint32_t>(param.data.substr(0, 4));;
    if (res->gas_left < gas_used) {
        return kContractError;
    }

    static constexpr size_t roundsSize = 4;
    static constexpr size_t stateVectorSize = 8 * 8;
    static constexpr size_t messageBlockSize = 16 * 8;
    static constexpr size_t offsetCounterSize = 8;
    static constexpr size_t finalBlockIndicatorSize = 1;
    static constexpr size_t totalInputSize = roundsSize + stateVectorSize + messageBlockSize +
        2 * offsetCounterSize + finalBlockIndicatorSize;
    if (param.data.size() != totalInputSize) {
        return kContractError;
    }

    auto const rounds = bignum::FromBigEndian<uint32_t>(param.data.substr(0, roundsSize));
    auto const stateVector = param.data.substr(roundsSize, stateVectorSize);
    auto const messageBlockVector = param.data.substr(
        roundsSize + stateVectorSize,
        messageBlockSize);
    auto const offsetCounter0 = param.data.substr(
        roundsSize + stateVectorSize + messageBlockSize,
        offsetCounterSize);
    auto const offsetCounter1 = param.data.substr(
        roundsSize + stateVectorSize + messageBlockSize + offsetCounterSize,
        offsetCounterSize);
    uint8_t const finalBlockIndicator = param.data[
        roundsSize + stateVectorSize + messageBlockSize + 2 * offsetCounterSize];
    if (finalBlockIndicator != 0 && finalBlockIndicator != 1) {
        return kContractError;
    }

    std::string blake2_res = blake2FCompression(
        rounds,
        stateVector,
        offsetCounter0,
        offsetCounter1,
        finalBlockIndicator,
        messageBlockVector);
    res->output_data = new uint8_t[blake2_res.size()];
    memcpy((void*)res->output_data, blake2_res.c_str(), blake2_res.size());
    res->output_size = blake2_res.size();
    memcpy(res->create_address.bytes,
        create_address_.c_str(),
        sizeof(res->create_address.bytes));
    res->gas_left -= gas_used;
    return kContractSuccess;
}

}  // namespace contract

}  // namespace tenon
