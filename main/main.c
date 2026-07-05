/*
 * ESP32-FIDO2 - Main entry point
 * Based on pico-openpgp and pico-keys-sdk (GPL v3 / AGPL v3)
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "rom/gpio.h"
#include "esp_task_wdt.h"
#include "tinyusb.h"
#include "tusb.h"
#include "compat/esp_compat.h"

#include "picokeys.h"
#include "usb/usb.h"
#include "led/led.h"
#include "flash.h"
#include "otp.h"
#include "pico_time.h"
#include "serial.h"
#include "random.h"
#include "hwrng.h"
#include "button.h"

#include "apdu.h"
#include "debug_mode.h"

#if CONFIG_DEBUG_STACK
#include "freertos/task.h"
static void log_stack_high_water(void) {
    static uint32_t _ticks = 0;
    if (++_ticks % (1000 / 10) != 0)  /* ~every 10 s at 10 ms/tick */
        return;
    TaskHandle_t tasks[] = { xTaskGetIdleTaskHandleForCPU(0), xTaskGetIdleTaskHandleForCPU(1) };
    for (int i = 0; i < 2; i++) {
        if (tasks[i]) {
            ESP_LOGI("stack", "core%d: %u bytes free",
                     i, (unsigned)uxTaskGetStackHighWaterMark(tasks[i]));
        }
    }
    ESP_LOGI("stack", "core0_loop: %u bytes free",
             (unsigned)uxTaskGetStackHighWaterMark(hcore0));
}
#else
#define log_stack_high_water()
#endif

app_t apps[16];
uint8_t num_apps = 0;
app_t *current_app = NULL;
const uint8_t *ccid_atr = NULL;

bool app_exists(const uint8_t *aid, size_t aid_len) {
    for (int a = 0; a < num_apps; a++) {
        if (aid_len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid, apps[a].aid[0])) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (app_exists(aid + 1, aid[0])) {
        return 1;
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

int select_app(const uint8_t *aid, size_t aid_len) {
    if (current_app && current_app->aid && (current_app->aid + 1 == aid ||
        (aid_len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid, current_app->aid[0])))) {
        current_app->select_aid(current_app, 0);
        return PICOKEYS_OK;
    }
    for (int a = 0; a < num_apps; a++) {
        if (aid_len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid, apps[a].aid[0])) {
            if (current_app) {
                if (current_app->aid && aid_len >= current_app->aid[0] &&
                    !memcmp(current_app->aid + 1, aid, current_app->aid[0])) {
                    current_app->select_aid(current_app, 1);
                    return PICOKEYS_OK;
                }
                if (current_app->unload) {
                    current_app->unload();
                }
            }
            current_app = &apps[a];
            if (current_app->select_aid(current_app, 1) == PICOKEYS_OK) {
                return PICOKEYS_OK;
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

WEAK int picokey_init(void) {
    return 0;
}

static const char *TAG = "esp32-fido2";

#define BOOT_PIN      GPIO_NUM_0

extern tinyusb_config_t tusb_cfg;
extern const uint8_t desc_config[];
extern char *string_desc_arr[];
extern char *string_desc_itf[];
extern uint8_t ITF_TOTAL;

TaskHandle_t hcore0 = NULL, hcore1 = NULL;

void execute_tasks(void);
void execute_tasks(void) {
#ifndef ESP_PLATFORM
    tud_task();
#endif
    usb_task();
    led_blinking_task();
}

static void core0_loop(void *arg) {
    (void)arg;
#ifdef ESP_PLATFORM
    /* Subscribe to the Task WDT so the periodic esp_task_wdt_reset()
       calls below are effective.  Without this the task is not in the
       WDT list and every call prints:
         task_wdt: esp_task_wdt_reset(...): task not found */
    esp_task_wdt_add(NULL);
#endif
    while (1) {
        execute_tasks();
        hwrng_task();
        flash_task();
        button_task();
        log_stack_high_water();
#ifdef ESP_PLATFORM
        /* Feed WDT — flash commits and long-running Ed25519 operations
           on core 1 must not starve core 0's watchdog. */
        esp_task_wdt_reset();
#endif
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

int app_main(void) {
    serial_init();
    random_init();
    otp_init_files();
    low_flash_init();
    file_scan_flash();
    init_rtc();
    phy_init();
    // CCID (OpenPGP) + HID (FIDO2) — no keyboard, no WCID
    phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_HID;
    phy_data.enabled_usb_itf_present = true;
    led_init();
    vTaskDelay(pdMS_TO_TICKS(100));  // USB hardware settle time
    usb_init();

    gpio_pad_select_gpio(BOOT_PIN);
    gpio_set_direction(BOOT_PIN, GPIO_MODE_INPUT);
    gpio_pulldown_dis(BOOT_PIN);

    tusb_cfg.string_descriptor[3] = pico_serial_str;
    if (phy_data.usb_product_present) {
        tusb_cfg.string_descriptor[2] = phy_data.usb_product;
    }
    static char tmps[5][32];
    const int max_desc_slots = 8 - 6;
    const int itf_desc_count = ITF_TOTAL < max_desc_slots ? ITF_TOTAL : max_desc_slots;
    for (int i = 0; i < itf_desc_count; i++) {
        strlcpy(tmps[i], tusb_cfg.string_descriptor[2], sizeof(tmps[0]));
        strlcat(tmps[i], " ", sizeof(tmps[0]));
        strlcat(tmps[i], string_desc_itf[i], sizeof(tmps[0]));
        tusb_cfg.string_descriptor[i+6] = tmps[i];
    }
    tusb_cfg.string_descriptor_count = 6 + itf_desc_count;
    tusb_cfg.configuration_descriptor = desc_config;

    tinyusb_driver_install(&tusb_cfg);

    picokey_init();

    ESP_LOGI(TAG, "ESP32-FIDO2 initialized");

    xTaskCreatePinnedToCore(core0_loop, "core0", 4096*ITF_TOTAL*2, NULL, CONFIG_TINYUSB_TASK_PRIORITY - 1, &hcore0, 0);

    return 0;
}
