add_executable(falco-test-engine main.cpp fixture_checks.cpp)
target_link_libraries(falco-test-engine falco_engine)
