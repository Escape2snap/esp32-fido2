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

# Suppress -Wreturn-type on third-party code for GCC 14+ compatibility
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-return-type)
