idf_component_register(SRC_DIRS "."
                    INCLUDE_DIRS "."
                    REQUIRES json libsodium unity)

# Override memory allocator to test OOM cases
target_compile_definitions(${COMPONENT_LIB} PRIVATE ICF_MALLOC=test_malloc)
