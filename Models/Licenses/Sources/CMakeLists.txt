add_library(Models.Licenses
	License.c
)

target_include_directories(Models.Licenses PUBLIC
		../Headers
		../../Commons/Headers
		${CMAKE_SOURCE_DIR}/Vendors/libGpG-Error/Includes
		${CMAKE_SOURCE_DIR}/Vendors/libGcrypt/Includes
	)

target_link_libraries(Models.Licenses PUBLIC Models.Commons)