set(OPENPGP_SRC_DIR ${CMAKE_CURRENT_LIST_DIR})

set(OPENPGP_SOURCES
    ${OPENPGP_SRC_DIR}/defs.c
    ${OPENPGP_SRC_DIR}/do.c
    ${OPENPGP_SRC_DIR}/files.c
    ${OPENPGP_SRC_DIR}/management.c
    ${OPENPGP_SRC_DIR}/openpgp.c
    ${OPENPGP_SRC_DIR}/piv.c
    ${OPENPGP_SRC_DIR}/cmd_activate_file.c
    ${OPENPGP_SRC_DIR}/cmd_change_pin.c
    ${OPENPGP_SRC_DIR}/cmd_challenge.c
    ${OPENPGP_SRC_DIR}/cmd_get_data.c
    ${OPENPGP_SRC_DIR}/cmd_import_data.c
    ${OPENPGP_SRC_DIR}/cmd_internal_aut.c
    ${OPENPGP_SRC_DIR}/cmd_keypair_gen.c
    ${OPENPGP_SRC_DIR}/cmd_mse.c
    ${OPENPGP_SRC_DIR}/cmd_pso.c
    ${OPENPGP_SRC_DIR}/cmd_put_data.c
    ${OPENPGP_SRC_DIR}/cmd_reset_retry.c
    ${OPENPGP_SRC_DIR}/cmd_select.c
    ${OPENPGP_SRC_DIR}/cmd_select_data.c
    ${OPENPGP_SRC_DIR}/cmd_terminate_df.c
    ${OPENPGP_SRC_DIR}/cmd_verify.c
    ${OPENPGP_SRC_DIR}/cmd_version.c
)

idf_component_register(
    SRCS ${OPENPGP_SOURCES}
    INCLUDE_DIRS ${OPENPGP_SRC_DIR}
    REQUIRES
        efuse
        mbedtls
        picokeys
        eddsa
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
