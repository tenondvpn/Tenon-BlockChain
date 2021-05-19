#pragma once

#include <string>
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif
#include "ssr/crypto.h"
#include "ssr/utils.h"
#include "ssr/netutils.h"
#ifdef __cplusplus
}
#endif
#include "common/utils.h"
#include "common/user_property_key_define.h"

namespace tenon {

namespace common {

enum {
    kStreamUnknown = 0,
    kStreamData = 1,
    kStreamConnect = 2,
    kStreamStopServer = 3,
};

static const uint32_t kCryptoCount = 128;
static const uint32_t kStreamMagicNum = (std::numeric_limits<uint32_t>::max)() ^ 2574554645u | 346356656u;
static const char* kRandomKey[kCryptoCount] = {
    "aDSFsdAdfGdfe45",
    "Dgedfgdsfw34dfd",
    "fdgdsfgdsfadfDF",
    "678gfdgSDFdfsdf",
    "h643Dfgaf245dfd",
    "2Dfa34sdfDSRFwerf2",
    "23asdgdf4sdfDSRFwrf2",
    "23sdj5thfDSRFwerf2",
    "4sdfDSRFsdfwwerf2",
    "sdfkjw5tyw4rDSRerf2",
     "h643Dfdgaf245dfd",
    "2Dfa34sdffDSRFwerf2",
    "23asasdgsdfDSRFwerf2",
    "234sgdffDSRFwerf2",
    "234sdfDSRFsdfwwerf2",
    "234sdfkjwgsd4rDSRFwerf2",
    "aDSFsdg34Gdfe45",
    "DgedfHGfw34dfd",
    "fdgdsDFDSsfadfDF",
    "678gfdgSDFdfsdf",
    "h643DfBV245dfd",
    "2DfMNNSRFwerf2",
    "23aQREDf4sdfDSRFwrf2",
    "XVShfDSRFwerf2",
    "4sFGFSRFsdfwwerf2",
    "sdfkjw5tyLJIerf2",
     "h643DfdgaPOKJdfd",
    "2DUIYHdfsdFwerf2",
    "23aMgsdfKHsdfDSRFwerf2",
    "234GHSDFRFwerf2",
    "23WQREfsdSRFsdfGDFerf2",
    "23GFDkjwgGDGFrf2",
    "aDSFsdAdfGdfe45",
    "DgedfgGSDw34dfd",
    "fdgdQSfadfDF",
    "678gfBFFFdfsdf",
    "h643DfgaXFDdfd",
    "2DfaGHTwerf2",
    "23asCSDEf4sdfDSRFwrf2",
    "23sYTFfDSRFwerf2",
    "4sdfDSCDDSfwwerf2",
    "sdfkjHVVSRerf2",
     "h64AWEgaf245dfd",
    "2DfaDFDSfDSRFwerf2",
    "23asBNBFsdfDSRFwerf2",
    "234sWWRDSRFwerf2",
    "23CDWfDSRFsdfwwerf2",
    "234sdfkjwgsd4rDSRFwerf2",
    "aDSJGTF34Gdfe45",
    "DgedfDASD4dfd",
    "fdgdsfssfadfDF",
    "678gfdgSliusdf",
    "h643Dsdf45dfd",
    "2DfMNNSRFwerf2",
    "23aQREDf4RFwrf2",
    "XVShfDSRBNFerf2",
    "4sFGFSRFsd789rf2",
    "sdfkjw5Qw12erf2",
     "FD43DfdgaPOKJdfd",
    "2jkYHfDSRFwerf2",
    "edfaMNJKHsdfDSRFwerf2",
    "lk34GHSDFRFwerf2",
    "nmWQREDSRFsdfwwerf2",
    "qw3GFDkjwgsd4rGFrf2",
     "aDSFhjkAdfGdfe45",
    "Dgedfgdsfghew34dfd",
    "fdgdsf23sfadfDF",
    "678gfdxcvwFdfsdf",
    "h643Dfmntgh245dfd",
    "2Dfa34sdfgdFwerf2",
    "23asdgwfDSRFwrf2",
    "23sdj5sdfSRFwerf2",
    "4sdfDSRFslwerf2",
    "sdfkjw5ttrDSRerf2",
     "h643Dfdef245dfd",
    "2Dfa34sdfvDSRFwerf2",
    "23asasdxcffDSRFwerf2",
    "234sgerSRFwerf2",
    "234sdfuinbgvgbwwerf2",
    "234sdfkqwerDSRFwerf2",
    "aDSFs234Gdfe45",
    "Dgedfcvxdfw34dfd",
    "fdgdsbrfeSsfadfDF",
    "6234dgSDFdfsdf",
    "h643DfBioihgfh",
    "2DfMNNSRFDFEg2",
    "23aQREDf4sdfD79872",
    "XVShfDSRF123f2",
    "4sFGFSRFSDwerf2",
    "sdfkjQRFLJIerf2",
     "h643DCDWaPOKJdfd",
    "2DUI213sdFwerf2",
    "23aMgdfDSRFwe22",
    "234GHSD12rf2",
    "23WQREfsdfFsdfGD1rf2",
    "23GcDkjwg12GFrf2",
    "aDSFsdAdfGdhry45",
    "Dge1223SDw34dfd",
    "fdgdQSfazxcqDF",
    "6as812BFFFdfsdf",
    "h643DfdfwFDdfd",
    "2DfaGHXXCrf2",
    "23asCSASSsdfDSRFwrf2",
    "23sYTFfDSghDf2",
    "4sdfDSCDkQ5rf2",
    "sdfQWDFVSRerf2",
     "h64AWEgaf2herdfd",
    "2DfaDFDSfDSXSDerf2",
    "23asBNBFsdijerf2",
    "234sWWsdfxccwerf2",
    "23CDWfDSRSDdfwwerf2",
    "234sdfkyuyrDSRFwerf2",
    "aDSJGTF34GdfXSD5",
    "Dg234dfDASD4dfd",
    "fdgdDGDSFDadfDF",
    "678gfdgXXSusdf",
    "h643DBBB5dfd",
    "2DfMNNSRNNNrf2",
    "23aQREDfWWRFwrf2",
    "XVShfDSRBCVrf2",
    "4sFGFSRFsYTrf2",
    "sdfkjw5QIUerf2",
     "FD43DfrtaPOKJdfd",
    "2jkYHfDSRFXCFf2",
    "edfaMNJKHsGGFwerf2",
    "lk34GHHHwerf2",
    "nmWQREDSRFsdfJJrf2",
    "qw3GFDkjwgsWWrf2"
};
class HeaderType {
public:
    static HeaderType* Instance();

    int32_t GetType(uint32_t rand_num) {
        if (rand_num >= kStreamConnectRangeMin && rand_num < kStreamConnectRangeMax) {
            return kStreamConnect;
        }

        if (rand_num >= kStreamDataMin && rand_num < kStreamDataMax) {
            return kStreamData;
        }

        if (rand_num >= kStreamStopServerMin && rand_num < kStreamStopServerMax) {
            return kStreamStopServer;
        }

        return kStreamUnknown;
    }

    int32_t GetRandNum(uint32_t type) {
        switch (type) {
            case kStreamData: {
                return (rand() % (kStreamDataMax - kStreamDataMin)) + kStreamDataMin;
            }
            case kStreamConnect: {
                return (rand() % (kStreamConnectRangeMax - kStreamConnectRangeMin)) + kStreamConnectRangeMin;
            }
            case kStreamStopServer: {
                return (rand() % (kStreamStopServerMax - kStreamStopServerMin)) + kStreamStopServerMin;
            }
            default:
                return 0;
        }
    }

    void Init() {
//         for (uint32_t i = 0; i < kCryptoCount; ++i) {
//             std::string seckey = std::to_string(i) + kRandomKey[i];
//             crypto_arr_[i] = crypto_init(
//                     seckey.c_str(),
//                     NULL,
//                     common::kDefaultEnocdeMethod.c_str());
//             if (crypto_arr_[i] == NULL) {
//                 exit(0);
//             }
// 
//             crypto_ectx_arr_[i] = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
//             crypto_dctx_arr_[i] = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
//             crypto_arr_[i]->ctx_init(crypto_arr_[i]->cipher, crypto_ectx_arr_[i], 1);
//             crypto_arr_[i]->ctx_init(crypto_arr_[i]->cipher, crypto_dctx_arr_[i], 0);
//         }
    }

    void Destroy() {
//         for (uint32_t i = 0; i < kCryptoCount; ++i) {
//             if (crypto_arr_[i] != NULL) {
//                 crypto_arr_[i]->ctx_release(crypto_ectx_arr_[i]);
//                 crypto_arr_[i]->ctx_release(crypto_dctx_arr_[i]);
//             }
// 
//             ss_free(crypto_arr_[i]);
//         }
    }

    int32_t Decrypt(uint32_t rand_num, buffer_t *buf) {
        uint32_t enc_idx = rand_num % kCryptoCount;
        std::string seckey = std::to_string(enc_idx) + kRandomKey[enc_idx];
        crypto_t* dec = crypto_init(
                seckey.c_str(),
                NULL,
                common::kDefaultEnocdeMethod.c_str());
        if (dec == NULL) {
            return 1;
        }

        cipher_ctx_t* dec_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
        dec->ctx_init(dec->cipher, dec_ctx, 0);
        int err = dec->decrypt(
                buf,
                dec_ctx,
                SOCKET_BUF_SIZE);
        dec->ctx_release(dec_ctx);
        ss_free(dec);
        return err;
    }

    int32_t Encrypt(uint32_t rand_num, buffer_t *buf) {
        uint32_t enc_idx = rand_num % kCryptoCount;
        std::string seckey = std::to_string(enc_idx) + kRandomKey[enc_idx];
        crypto_t* enc = crypto_init(
                seckey.c_str(),
                NULL,
                common::kDefaultEnocdeMethod.c_str());
        if (enc == NULL) {
            return 1;
        }

        cipher_ctx_t* enc_ctx = (cipher_ctx_t*)ss_malloc(sizeof(cipher_ctx_t));
        enc->ctx_init(enc->cipher, enc_ctx, 1);
        int err = crypto_arr_[enc_idx]->encrypt(
                buf,
                enc_ctx,
                SOCKET_BUF_SIZE);
        enc->ctx_release(enc_ctx);
        ss_free(enc);
        return err;
    }

private:
    HeaderType() {
        memset(crypto_arr_, 0, kCryptoCount * sizeof(crypto_arr_[0]));
        memset(crypto_ectx_arr_, 0, kCryptoCount * sizeof(crypto_ectx_arr_[0]));
        memset(crypto_dctx_arr_, 0, kCryptoCount * sizeof(crypto_dctx_arr_[0]));
        Init();
    }

    ~HeaderType() {
        Destroy();
    }

    static const uint32_t kStreamConnectRangeMin = 0u;
    static const uint32_t kStreamConnectRangeMax = 1987434u;
    static const uint32_t kStreamDataMin = 1987434u;
    static const uint32_t kStreamDataMax = 2987434u;
    static const uint32_t kStreamStopServerMin = 2987434u;
    static const uint32_t kStreamStopServerMax = 3987434u;

    crypto_t* crypto_arr_[kCryptoCount];
    cipher_ctx_t* crypto_ectx_arr_[kCryptoCount];
    cipher_ctx_t* crypto_dctx_arr_[kCryptoCount];

    DISALLOW_COPY_AND_ASSIGN(HeaderType);
};

}  // namespace common

}  // namespace tenon
