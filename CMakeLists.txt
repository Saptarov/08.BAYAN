cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 17)
set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VESRION 0.0.${PATCH_VERSION})
project(bayan VERSION ${PROJECT_VESRION} LANGUAGES CXX)
FIND_PACKAGE( Boost 1.40 COMPONENTS program_options REQUIRED )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE MAIN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*)
file(GLOB_RECURSE TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/test/*)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "Source" FILES ${MAIN_SRC} ${TEST_SRC})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
find_package(Boost COMPONENTS system filesystem REQUIRED)
add_executable(
    ${PROJECT_NAME}
    ${MAIN_SRC}
)

target_link_libraries(
    ${PROJECT_NAME}
    ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_SYSTEM_LIBRARY}

    )

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4
    )
else ()
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -Werror
    )
endif()

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT example@example.com)

include(CPack)
