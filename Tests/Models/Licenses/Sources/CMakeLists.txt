add_executable(Test_License
    ./Test_License.c
)

# Linking to the library
set(STATIC_LIB_PATH ${CMAKE_BINARY_DIR}/Vendors)

target_include_directories(Test_License PUBLIC ../Headers)

target_link_libraries(Test_License
	Models.Licenses
	${STATIC_LIB_PATH}/libGcrypt/Libs/libgcrypt.a
    ${STATIC_LIB_PATH}/libGpG-Error/Libs/libgpg-error.a
    cmocka
)

add_test(NAME Test_License COMMAND Test_License)