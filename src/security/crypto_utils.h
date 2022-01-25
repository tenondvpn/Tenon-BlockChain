#pragma once

#include <memory>
#include <vector>

#include "common/utils.h"
#include "common/log.h"

#define CRYPTO_DEBUG(fmt, ...) TENON_DEBUG("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_INFO(fmt, ...) TENON_INFO("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_WARN(fmt, ...) TENON_WARN("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_ERROR(fmt, ...) TENON_ERROR("[crypto]" fmt, ## __VA_ARGS__)

namespace tenon {

namespace security {

enum SecurityErrorCode {
    kSecuritySuccess = 0,
    kSecurityError = 1,
};

typedef std::vector<uint8_t> bytes;
static const uint32_t kPublicCompresssedSizeBytes = 33u;
static const uint32_t kCommitPointHashSize = 32u;
static const uint32_t kChallengeSize = 32u;
static const uint32_t kResponseSize = 32u;
static const uint8_t kSecondHashFunctionByte = 0x01;
static const uint8_t kThirdHashFunctionByte = 0x11;
static const uint32_t kCommitSecretSize = 32u;
static const uint32_t kCommitPointSize = 33u;
static const uint32_t kPrivateKeySize = 32u;
static const uint32_t kPublicKeySize = 33u;
static const uint32_t kPublicKeyUncompressSize = 65u;
static const uint32_t kTenonAddressSize = 20u;
static const uint32_t kSignatureSize = 64u;

bool IsValidPublicKey(const std::string& pubkey);
bool IsValidSignature(const std::string& ch, const std::string& res);

}  // namespace security

}  // namespace tenon
