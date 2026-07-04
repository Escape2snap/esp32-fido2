# EdDSA (Ed25519/Ed448) support for ESP32-FIDO2
set(FORK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/mbedtls-fork)
set(EDDSA_SRC_DIR ${CMAKE_CURRENT_LIST_DIR})

set(EDDSA_SOURCES
    ${FORK_DIR}/library/eddsa.c
    ${EDDSA_SRC_DIR}/eddsa_ecp_extras.c
)

set(EDDSA_INCLUDE_DIRS
    ${EDDSA_SRC_DIR}
    ${FORK_DIR}/include
    ${FORK_DIR}/library
)

idf_component_register(
    SRCS ${EDDSA_SOURCES}
    INCLUDE_DIRS ${EDDSA_INCLUDE_DIRS}
    REQUIRES mbedtls
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MBEDTLS_EDDSA_C=1
    MBEDTLS_ECP_DP_ED25519_ENABLED=1
    MBEDTLS_ECP_DP_ED448_ENABLED=1
)

set_source_files_properties(
    ${FORK_DIR}/library/eddsa.c
    PROPERTIES COMPILE_FLAGS "-Wno-error=switch -Wno-switch -Wno-error=unused-function -Wno-error=unused-parameter"
)
set_source_files_properties(
    ${EDDSA_SRC_DIR}/eddsa_ecp_extras.c
    PROPERTIES COMPILE_FLAGS "-Wno-error=switch -Wno-switch"
)
