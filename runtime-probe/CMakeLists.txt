cmake_minimum_required(VERSION 3.20)
project(NFSTR_ITC_RuntimeProbe LANGUAGES CXX)

add_library(NFSTR_ITC_RuntimeProbe SHARED runtime_probe.cpp)
target_compile_features(NFSTR_ITC_RuntimeProbe PRIVATE cxx_std_17)
target_compile_definitions(NFSTR_ITC_RuntimeProbe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(NFSTR_ITC_RuntimeProbe PRIVATE psapi)
set_target_properties(NFSTR_ITC_RuntimeProbe PROPERTIES
    PREFIX ""
    OUTPUT_NAME "NFSTR_ITC_RuntimeProbe"
    SUFFIX ".asi"
)

if(MSVC)
    target_compile_options(NFSTR_ITC_RuntimeProbe PRIVATE /W4 /O2 /EHsc)
endif()
