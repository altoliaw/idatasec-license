add_library(Sources.LicenseGenerationController
    ./LicenseMainCaller.c
)

# Linking to the library
set(STATIC_LIB_PATH ${CMAKE_BINARY_DIR}/Vendors)

target_include_directories(Sources.LicenseGenerationController PUBLIC 
    ${CMAKE_SOURCE_DIR}/Headers/LicenseGenerationController
    ${CMAKE_SOURCE_DIR}/Models/Licenses/Headers
)

target_link_libraries(Sources.LicenseGenerationController
    Models.Licenses
    ${STATIC_LIB_PATH}/libGcrypt/Libs/libgcrypt.a
    ${STATIC_LIB_PATH}/libGpG-Error/Libs/libgpg-error.a
    cmocka
)
