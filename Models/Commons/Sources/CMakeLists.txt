add_library(Models.Commons
	Time.c
	EncodePrototype.c
	EncodeBase64.c
)

target_include_directories(Models.Licenses PUBLIC 
		../Headers 
)