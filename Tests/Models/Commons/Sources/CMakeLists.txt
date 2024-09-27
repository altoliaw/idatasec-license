# # Creating an execution in each model
# add_executable(
# 	Tests.Commons
# 	Test_StringImplement.cpp
# 	Test_HashTable.cpp
# )
	
# # linking to the headers
# target_include_directories(Tests.Commons PUBLIC ../Headers ../../../../Models/Commons/Headers)

# # linking to the gtest library
# target_link_libraries(
# 	Tests.Commons
# 	Models.Commons
# 	GTest::gtest_main
# )
		
# include(GoogleTest)

# # Registering the tests
# add_test(NAME Tests.Commons COMMAND Tests.Commons --gtest_color=yes)