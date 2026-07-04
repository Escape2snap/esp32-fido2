set(PICOKEYS_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)

set(PICOKEYS_SOURCES
    ${PICOKEYS_SRC_DIR}/apdu.c
    ${PICOKEYS_SRC_DIR}/asn1.c
    ${PICOKEYS_SRC_DIR}/button.c
    ${PICOKEYS_SRC_DIR}/crypto_utils.c
    ${PICOKEYS_SRC_DIR}/eac.c
    ${PICOKEYS_SRC_DIR}/pico_time.c
    ${PICOKEYS_SRC_DIR}/rescue.c
    ${PICOKEYS_SRC_DIR}/serial.c
    ${PICOKEYS_SRC_DIR}/tlv.c
    ${PICOKEYS_SRC_DIR}/fs/file.c
    ${PICOKEYS_SRC_DIR}/fs/flash.c
    ${PICOKEYS_SRC_DIR}/fs/low_flash.c
    ${PICOKEYS_SRC_DIR}/fs/otp.c
    ${PICOKEYS_SRC_DIR}/fs/phy.c
    ${PICOKEYS_SRC_DIR}/led/led.c
    ${PICOKEYS_SRC_DIR}/led/led_neopixel.c
    ${PICOKEYS_SRC_DIR}/led/led_pico.c
    ${PICOKEYS_SRC_DIR}/rng/hwrng.c
    ${PICOKEYS_SRC_DIR}/rng/random.c
    ${PICOKEYS_SRC_DIR}/usb/ccid/ccid.c
    ${PICOKEYS_SRC_DIR}/usb/hid/hid.c
    ${PICOKEYS_SRC_DIR}/usb/usb.c
    ${PICOKEYS_SRC_DIR}/usb/usb_descriptors.c
)

set(PICOKEYS_INCLUDE_DIRS
    ${PICOKEYS_SRC_DIR}
    ${PICOKEYS_SRC_DIR}/fs
    ${PICOKEYS_SRC_DIR}/usb
    ${PICOKEYS_SRC_DIR}/usb/hid
    ${PICOKEYS_SRC_DIR}/rng
    ${PICOKEYS_SRC_DIR}/led
    ${PICOKEYS_SRC_DIR}/compat
)

idf_component_register(
    SRCS ${PICOKEYS_SOURCES}
    INCLUDE_DIRS ${PICOKEYS_INCLUDE_DIRS}
    REQUIRES
        bootloader_support
        driver
        efuse
        esp_partition
        esp_tinyusb
        esp_timer
        log
        mbedtls
        nvs_flash
        wear_levelling
        zorxx__neopixel
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    USB_VID=0x2E8A
    USB_PID=0x10FF
    USB_ITF_HID=1
    DEBUG_APDU=0
)
