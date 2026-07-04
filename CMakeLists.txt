cmake_minimum_required(VERSION 3.13)

set(EXTRA_COMPONENT_DIRS
    components/picokeys
    components/openpgp
    components/fido
    components/tinycbor
)

add_compile_definitions(
    USB_ITF_CCID=1
    USB_ITF_WCID=1
    USB_ITF_HID=1
    CFG_TUSB_MCU=OPT_MCU_ESP32S3
)

set(CFG_TUSB_CONFIG_FILE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/components/picokeys/src/usb/tusb_config.h")
add_compile_definitions(CFG_TUSB_CONFIG_FILE="${CFG_TUSB_CONFIG_FILE_PATH}")

# Auto-create device_config.h from template if missing
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/main/device_config.h")
    configure_file(
        "${CMAKE_SOURCE_DIR}/main/device_config.old.h"
        "${CMAKE_SOURCE_DIR}/main/device_config.h"
        COPYONLY)
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(esp32_fido2 C CXX ASM)
