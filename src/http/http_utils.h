#pragma once

#include "common/utils.h"

namespace tenon {

namespace http {

enum HttpStatusCode: int32_t {
    kHttpSuccess = 0,
    kHttpError = 1,
};

static const std::string kHttpParamTaskId = "tid";

};  // namespace tenon

};  // namespace tenon
