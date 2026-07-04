set(FIDO_SRC_DIR ${CMAKE_CURRENT_LIST_DIR})

set(FIDO_SOURCES
    ${FIDO_SRC_DIR}/cbor.c
    ${FIDO_SRC_DIR}/cbor_client_pin.c
    ${FIDO_SRC_DIR}/cbor_config.c
    ${FIDO_SRC_DIR}/cbor_cred_mgmt.c
    ${FIDO_SRC_DIR}/cbor_get_assertion.c
    ${FIDO_SRC_DIR}/cbor_get_info.c
    ${FIDO_SRC_DIR}/cbor_large_blobs.c
    ${FIDO_SRC_DIR}/cbor_make_credential.c
    ${FIDO_SRC_DIR}/cbor_reset.c
    ${FIDO_SRC_DIR}/cbor_selection.c
    ${FIDO_SRC_DIR}/cbor_vendor.c
    ${FIDO_SRC_DIR}/cmd_authenticate.c
    ${FIDO_SRC_DIR}/cmd_register.c
    ${FIDO_SRC_DIR}/cmd_version.c
    ${FIDO_SRC_DIR}/credential.c
    ${FIDO_SRC_DIR}/fido.c
    ${FIDO_SRC_DIR}/fido_ef.c
    ${FIDO_SRC_DIR}/known_apps.c
)

idf_component_register(
    SRCS ${FIDO_SOURCES}
    INCLUDE_DIRS ${FIDO_SRC_DIR}
    PRIV_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/third-party/mbedtls-fork/include ${CMAKE_SOURCE_DIR}/components/eddsa
    REQUIRES
        picokeys
        mbedtls
        tinycbor
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
