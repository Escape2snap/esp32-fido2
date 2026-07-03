idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES
        picokeys
        openpgp
        fido
        esp_tinyusb
        mbedtls
        driver
        efuse
        nvs_flash
)
