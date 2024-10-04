cmake_minimum_required(VERSION 3.14)
project(idatasec-license)

#setting standard liberary, C
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# [C++ Settings]
## GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# [Testing Flag]
## Setting the option to determine whether the test is enabled or the compile (for windows) shall be executed
## When users feel like use cmake instructions for executing non-test code, the instructions are shown as below,
## "cmake -S . -B build -DBUILD_TESTS=OFF && cmake --build build".
option(BUILD_TEST "The default testing variable is on" ON)

## Enableing test
if (BUILD_TEST)
  enable_testing()
endif()

# [Goolge Test Settings]
# ## Goolge test requires
# if (BUILD_TEST)
#   include(FetchContent)
#   FetchContent_Declare(
#     googletest
#     URL https://github.com/google/googletest/archive/305e5a238b3c8d11266fbafd85520fb6b3184851.zip
#   )
#   # For Windows: Prevent overriding the parent project's compiler/linker settings
#   set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
#   FetchContent_MakeAvailable(googletest)
# endif()

# [Involved Files When Compiling]
## Copying the dependent files of the project (cfg, ini files or files users feel like opening)
if (BUILD_TEST)
configure_file(${CMAKE_SOURCE_DIR}/Settings/.Ini/globalCompiling.ini ${CMAKE_BINARY_DIR}/Settings/.Ini/globalCompiling.ini COPYONLY)
endif()

# Others involved in the testing process and compiling process
configure_file(${CMAKE_SOURCE_DIR}/Settings/.Json/SizingMain.json ${CMAKE_BINARY_DIR}/Settings/.Json/SizingMain.json COPYONLY)

## Copying the third party software into the Vendors folder and the Outputs for testing
file(COPY ${CMAKE_SOURCE_DIR}/Vendors DESTINATION ${CMAKE_BINARY_DIR})
file(COPY ${CMAKE_SOURCE_DIR}/Outputs DESTINATION ${CMAKE_BINARY_DIR})


# [Included Directories]
## Opening the subdirectory for the next works
add_subdirectory(Models)
# add_subdirectory(Sources)

## When the testing function is set as "ON"
if (BUILD_TEST)
  add_subdirectory(Tests)
else() # The necessary directory when compiling on Windows
  add_subdirectory(Apps)
endif()