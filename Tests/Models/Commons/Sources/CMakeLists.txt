add_executable(Test_Time
    ./Test_Time.c
)

# Linking to the library
set(STATIC_LIB_PATH ${CMAKE_BINARY_DIR}/Vendors)

target_include_directories(Test_Time PUBLIC 
    ../Headers
    ${CMAKE_SOURCE_DIR}/Models/Commons/Headers
)

target_link_libraries(Test_Time
    Models.Commons
    cmocka
)

add_test(NAME Test_Time COMMAND Test_Time)

#########################################
add_executable(Test_EncodeBase64
    ./Test_EncodeBase64.c
)

# Linking to the library
set(STATIC_LIB_PATH ${CMAKE_BINARY_DIR}/Vendors)

target_include_directories(Test_EncodeBase64 PUBLIC 
    ../Headers
    ${CMAKE_SOURCE_DIR}/Models/Commons/Headers
)

target_link_libraries(Test_EncodeBase64
    Models.Commons
    cmocka
)

add_test(NAME Test_EncodeBase64 COMMAND Test_EncodeBase64)