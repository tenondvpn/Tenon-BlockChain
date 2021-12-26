#pragma once

#include <string.h>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PropertyConfigurator.hh"

#ifdef _WIN32
#define LEGO_LOG_FILE_NAME strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__
#else
#define LEGO_LOG_FILE_NAME strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#endif

#define LOG_INS log4cpp::Category::getInstance(std::string("sub1"))
#ifdef _WIN32

#ifdef NDEBUG
#define DEBUG(fmt, ...)
#else
#define DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#endif

#define TENON_INFO(fmt, ...)  do {\
    LOG_INS.info("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_WARN(fmt, ...)  do {\
    LOG_INS.warn("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_ERROR(fmt, ...)  do {\
    LOG_INS.error("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#else

#ifdef NDEBUG
#define DEBUG(fmt, ...)
#define TENON_DEBUG(fmt, ...)
#else
#define DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#define TENON_DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#endif

#define TENON_INFO(fmt, ...)  do {\
    LOG_INS.info("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_WARN(fmt, ...)  do {\
    LOG_INS.warn("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_ERROR(fmt, ...)  do {\
    LOG_INS.error("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#endif // _WIN32

#ifdef LOG
#undef LOG
#endif // LOG
#define LOG(level) LOG_INS << level << "[" << LEGO_LOG_FILE_NAME << ": " << __LINE__ << "]" 

#ifdef FOR_CONSOLE_DEBUG
#undef DEBUG
#undef TENON_INFO
#undef TENON_WARN
#undef TENON_ERROR

#define DEBUG(fmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#define TENON_DEBUG(fmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_INFO(fmt, ...)  do {\
    printf("[INFO][%s][%s][%d] " fmt "\n", LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_WARN(fmt, ...)  do {\
    printf("[WARN][%s][%s][%d] " fmt "\n", LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define TENON_ERROR(fmt, ...)  do {\
    printf("[ERROR][%s][%s][%d] " fmt "\n", LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#endif
