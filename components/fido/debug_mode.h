/*
 * Debug mode helpers — controlled by Kconfig (idf.py menuconfig → Debug Mode)
 *
 * Provides performance timing, APDU tracing, and WDT feeding macros
 * that expand to nothing when debugging is disabled.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef _DEBUG_MODE_H_
#define _DEBUG_MODE_H_

#include "esp_log.h"

/* ------------------------------------------------------------------ */
/*  Performance timing                                                */
/* ------------------------------------------------------------------ */
#if defined(CONFIG_DEBUG_ENABLE) && defined(CONFIG_DEBUG_PERF)
#include "esp_timer.h"
#define PERF_TAG "perf"
#define PERF_START()  uint64_t _perf_start = esp_timer_get_time()
#define PERF_END(msg) ESP_LOGI(PERF_TAG, "%s: %lld us", msg, esp_timer_get_time() - _perf_start)
#else
#define PERF_START()
#define PERF_END(msg)
#endif

/* ------------------------------------------------------------------ */
/*  APDU / data hex dump                                              */
/* ------------------------------------------------------------------ */
#if defined(CONFIG_DEBUG_ENABLE) && defined(CONFIG_DEBUG_APDU_HEX)
#include <stdio.h>
#include <inttypes.h>
static inline void debug_apdu_hex(const char *tag, const uint8_t *data, size_t len) {
    printf("[%s] ", tag);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}
#define APDU_TRACE(tag, data, len) debug_apdu_hex(tag, data, len)
#else
#define APDU_TRACE(tag, data, len)
#endif

/* ------------------------------------------------------------------ */
/*  WDT feeding (useful for long loops like ed25519 scalar mult)      */
/* ------------------------------------------------------------------ */
#if defined(CONFIG_DEBUG_ENABLE) && defined(CONFIG_DEBUG_WDT_FEED)
#include "esp_task_wdt.h"
/* Call this inside long-running loops at CONFIG_DEBUG_WDT_FEED_INTERVAL_MS */
#define WDT_FEED() do {                                     \
    static uint64_t _last_feed = 0;                         \
    uint64_t _now = esp_timer_get_time() / 1000;            \
    if (_now - _last_feed >= CONFIG_DEBUG_WDT_FEED_INTERVAL_MS) { \
        esp_task_wdt_reset();                               \
        _last_feed = _now;                                  \
    }                                                       \
} while (0)
#else
#define WDT_FEED()
#endif

#endif /* _DEBUG_MODE_H_ */
