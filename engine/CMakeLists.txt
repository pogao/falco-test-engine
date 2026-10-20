add_executable(falco-test-engine main.cpp fixture_checks.cpp ast_json.cpp)
target_link_libraries(falco-test-engine falco_engine)
# config_falco.h, for FALCO_VERSION and FALCOSECURITY_LIBS_VERSION
target_include_directories(falco-test-engine PRIVATE ${CMAKE_BINARY_DIR}/userspace/falco)
