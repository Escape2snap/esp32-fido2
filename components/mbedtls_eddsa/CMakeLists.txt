idf_component_register(
    SRCS
        "eddsa.c"
        "eddsa_shim.c"
    INCLUDE_DIRS "."
    INCLUDE_DIRS "include"
    REQUIRES mbedtls
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    MBEDTLS_EDDSA_C=1
    MBEDTLS_ECP_DP_ED25519_ENABLED=1
    MBEDTLS_ECP_DP_ED448_ENABLED=1
)

# The fork's eddsa.c uses case values not in the ESP-IDF mbedtls ecp_group_id enum
set_source_files_properties(
    "${CMAKE_CURRENT_LIST_DIR}/eddsa.c"
    PROPERTIES COMPILE_FLAGS "-Wno-error=switch -Wno-switch-enum"
)
