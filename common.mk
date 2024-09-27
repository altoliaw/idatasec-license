# The file is for implementing the values which are used to 
# be arguments for passing to the sub makefiles. Generally, the
# file only is referred by the Makefile of the project. When editing the 
# file, all composition shall use the tabs.
#
# @author Nick
# @date 2024/09/20

# ######## [Multiple Line Definitions]: For Defining the variable
define arguments
{											\
	\"CC\":				\"${CC}\",			\
	\"STD\":			\"${STD}\",			\
	\"CMPOPT\":			\"${CMPOPT}\",		\
	\"DETAILINFO\":		\"${DETAILINFO}\",	\
	\"WALL\":			\"${WALL}\",		\
	\"FMSG\":			\"${FMSG}\",		\
	\"CFLAGS\":			\"${CFLAGS}\",		\
	\"LDFLAGS\":		\"${LDFLAGS}\",		\
	\"LDLIBS\":			\"${LDLIBS}\",		\
	\"OS\":				\"${OS}\",			\
	\"SUDO\":			\"${SUDO}\"			\
}
endef