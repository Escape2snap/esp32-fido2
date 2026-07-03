set(TINYCBOR_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/tinycbor)

idf_component_register(
    SRCS
        ${TINYCBOR_DIR}/src/cborencoder.c
        ${TINYCBOR_DIR}/src/cborparser.c
        ${TINYCBOR_DIR}/src/cborparser_dup_string.c
    INCLUDE_DIRS
        ${TINYCBOR_DIR}/src
)

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
