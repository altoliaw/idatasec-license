# Opening the subdirectory for the next works
add_subdirectory(Commons)
add_subdirectory(FileParsers)

if (NOT BUILD_TEST)
	add_subdirectory(PCAP)
endif()