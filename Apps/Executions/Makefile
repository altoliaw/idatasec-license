# The Makefile for the execution from SizingMain.cpp
#
# @author Nick
# @date 2024/09/24

# ######## [Environment Setting]
# The variables will be obtain the Makefile from the project; using the "searchElement" with jq to search the contents
# from the Shells/installVendor.sh
PLAIN_ARGUMENTS	:=  $(shell source ${projectDir}/Shells/codecUtilities.sh && echo $$(acsiiHexToString "${ARGUMENTS}"))

# ######## [Necessary Common MakeFile Variables Included]
include ${CommonTempMakefile}

# If someone feel like using the definitions that users define, please remove the comment and fill in the suitable terms.
# CC			=
# STD			=
# CMPOPT		=
# DETAILINFO	=
# WALL		=
# FMSG		=
CFLAGS		=
LDFLAGS		=-LVendors/libGpG-Error/Libs -LVendors/libGcrypt/Libs
LDLIBS		=-lgpg-error -lgcrypt -lpthread

# Replacing terms by using $(.) from Makefile function
# CFLAGS		:=	$(subst -I,-I${projectDir}/,${CFLAGS})
# Replacing terms by using $(.) from Makefile function
LDFLAGS		:= $(subst -L,-L${projectDir}/,${LDFLAGS})

# ######## [Variable Definition]
Models			:=	Apps.Executions
Duration		:=
### The folder for the exection
Bin				:=	Bin

# ######## [Necessary MakeFile Variables Included]
include ${TempMakefile}

# ######## [Implicit Rules]
# The definition for the basic element in the Makefile
.Suffixs: .c .h .cpp .hpp


# ######## [Phonies]
# The top level of the Makefile
.Phony: all
all: \
	startTime \
	${Apps}/SizingMain.exe \
	endTime


# ######## [Compiling Items]
# Start time
startTime:
	@$(eval Duration := $(shell source ${projectDir}/Shells/compiledStringMessage.sh && echo $$(startingString "${Models}")))
# End Time
endTime:
	@echo $(shell source ${projectDir}/Shells/compiledStringMessage.sh && echo $$(endingString "${Models}" "${Duration}"))

# SizingMain.exe
${Apps}/SizingMain.exe: 
	${CC} ${STD} ${CMPOPT} ${DETAILINFO} ${WALL} ${CFLAGS} ${FMSG} -o ${projectDir}/${Bin}/LicenseGenerationMain.exe ${Apps}/LicenseGenerationMain.o \
	${Sources.LicenseGenerationController}/LicenseMainCaller.o \
	${Commons.Sources}/EncodePrototype.o \
	${Commons.Sources}/EncodeBase64.o \
	${Commons.Sources}/Time.o \
	${Licenses.Sources}/License.o \
	${LDFLAGS} \
	${LDLIBS}
