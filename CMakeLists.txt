cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_SYSTEM_NAME Windows)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++ CACHE STRING "MinGW cross compiler")
    project(AdaptiHound CXX)
endif()

function(adaptihound_module target source output)
    add_library(${target} OBJECT ${source}/src/entry.cpp)
    set_target_properties(${target} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/_include)
    target_compile_options(${target} PRIVATE -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-weak -Os -Wall -Wextra -Werror -fno-builtin -fno-stack-protector -mno-stack-arg-probe)
    target_compile_definitions(${target} PRIVATE BOF)
    add_custom_target(${target}_artifact ALL
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/_bin/AdaptiHound
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:${target}> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/AdaptiHound/${output}.x64.o
        DEPENDS ${target})
endfunction()
adaptihound_module(adaptihound_ad ADHound-BOF ad)
adaptihound_module(adaptihound_freeipa IPAHound-BOF freeipa)
add_custom_target(adaptihound DEPENDS adaptihound_ad_artifact adaptihound_freeipa_artifact)
