#pragma once

#include <map>

#include "common/utils.h"

namespace tenon {

namespace http {

enum HttpStatusCode: int32_t {
    kHttpSuccess = 0,
    kHttpError = 1,
    kAccountNotExists = 2,
    kBalanceInvalid = 3,
    kShardIdInvalid = 4,
    kSignatureInvalid = 5,
};

static const std::string kHttpParamTaskId = "tid";
static const std::map<int, std::string> kStatusMap = {
    {kHttpSuccess, "kHttpSuccess"},
    {kHttpError, "kHttpError"},
    {kAccountNotExists, "kAccountNotExists"},
    {kBalanceInvalid, "kBalanceInvalid"},
    {kShardIdInvalid, "kShardIdInvalid"},
    {kSignatureInvalid, "kSignatureInvalid"},
};

};  // namespace tenon

};  // namespace tenon
