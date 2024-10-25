add_executable(Test_LicenseMainCaller
    ./Test_LicenseMainCaller.c
)

# Linking to the library
set(STATIC_LIB_PATH ${CMAKE_BINARY_DIR}/Vendors)

target_include_directories(Test_LicenseMainCaller PUBLIC 
    ${CMAKE_SOURCE_DIR}/Headers/LicenseGenerationController
    ${CMAKE_SOURCE_DIR}/Models/Licenses/Headers
)

target_link_libraries(Test_LicenseMainCaller
    Sources.LicenseGenerationController
    Models.Licenses
    ${STATIC_LIB_PATH}/libGcrypt/Libs/libgcrypt.a
    ${STATIC_LIB_PATH}/libGpG-Error/Libs/libgpg-error.a
    cmocka
)

add_test(NAME Test_LicenseMainCaller COMMAND Test_LicenseMainCaller)