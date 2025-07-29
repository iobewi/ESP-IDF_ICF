idf_component_register(SRCS "test_icf.c"
                       PRIV_REQUIRES json libsodium unity)

# Override memory allocator to test OOM cases
target_compile_definitions(${COMPONENT_LIB} PRIVATE ICF_MALLOC=test_malloc)
