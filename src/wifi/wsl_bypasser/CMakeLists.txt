idf_component_register(
    SRCS "wsl_bypasser.c"
)
target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)