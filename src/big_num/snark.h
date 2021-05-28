#pragma once

#pragma warning(push)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <boost/multiprecision/cpp_int.hpp>
#pragma warning(pop)
#pragma GCC diagnostic pop

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "common/utils.h"

using namespace boost::multiprecision::literals;
using bigint = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<>>;
using u256 = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<256, 256, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked, void>>;

namespace tenon {

namespace bignum {

class Snark {
public:
    static Snark* Instance();
    std::string AltBn128PairingProduct(const std::string& in);
    std::string AltBn128G1Add(const std::string& in);
    std::string AltBn128G1Mul(const std::string& in);

private:
    Snark() {}
    ~Snark() {}
    void InitLibSnark();
    libff::bigint<libff::alt_bn128_q_limbs> ToLibsnarkBigint(const std::string& in_x);
    std::string FromLibsnarkBigint(libff::bigint<libff::alt_bn128_q_limbs> const& b);
    libff::alt_bn128_Fq DecodeFqElement(const std::string& data);
    libff::alt_bn128_G1 DecodePointG1(const std::string& data);
    std::string EncodePointG1(libff::alt_bn128_G1 p);
    libff::alt_bn128_Fq2 DecodeFq2Element(const std::string& data);
    libff::alt_bn128_G2 DecodePointG2(const std::string& data);

    DISALLOW_COPY_AND_ASSIGN(Snark);
};

};  // namespace bignum

};  // namespace tenon