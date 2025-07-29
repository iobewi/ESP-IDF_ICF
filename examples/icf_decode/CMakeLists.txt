idf_build_set_property(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/components" APPEND)
set(COMPONENT_REQUIRES icf)

set(srcs "main/main.c")

idf_component_register(SRCS ${srcs} REQUIRES ${COMPONENT_REQUIRES})
