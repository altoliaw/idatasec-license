# The Makefile for Commons
#
# @author Nick
# @date 2024/09/24

# ######## [Necessary Common MakeFile Variables Included]
include ${CommonTempMakefile}

# If someone feel like using the definitions that users define, please remove the comment and fill in the suitable terms.
# CC			=
# STD			=
# CMPOPT		=
# DETAILINFO	=
# WALL		=
# FMSG		=
# CFLAGS		=
# LDFLAGS		=
# LDLIBS		=

# Replacing terms by using $(.) from Makefile function
# CFLAGS		:=	$(subst -I,-I${projectDir}/,${CFLAGS})
# Replacing terms by using $(.) from Makefile function
# LDFLAGS		:= $(subst -L,-L${projectDir}/,${LDFLAGS})

# ######## [Environment Setting]
# Necessary MakeFile Variables Included
include ${TempMakefile}

# ######## [Variable Definition]
Models			:=	Models.Commons
Duration		:=
Commons.Headers	:=	${projectDir}/Models/Commons/Headers
Commons.Sources	:=	${projectDir}/Models/Commons/Sources

# ######## [Passing the Variable Definition into the File]
# Verifying the content the file, ${TempMakefile} (tmp.mk from the project);
# the regular expression is e.g., grep -q "^PCAP\.Headers\s*\(:\)\?=" /home/dbsecure/native-sizing/tmp.mk && echo $?
# when the returned value is 0, the string contains the pattern; when the returned values are other values except 0, 
# the string does not contain the pattern
IsExisted	:=


# ######## [Implicit Rules]
# The definition for the basic element in the Makefile
.Suffixs: .c .h .cpp .hpp


# ######## [Phonies]
# The top level of the Makefile
.Phony: all
all: \
	startTime \
	${Commons.Sources}/Time.o \
	${Commons.Sources}/EncodePrototype.o \
	${Commons.Sources}/EncodeBase64.o \
	endTime
# Adding the Makefile's variables shall be added into the ${TempMakefile} file
	@make information


# This section is for determining if the Makefile's variables shall be added into the 
# ${TempMakefile} file
.Phony: information
information:
# Verifying the content the file, ${TempMakefile} (tmp.mk from the project) to
# determine if the variable in the Makefile shall be added into the ${TempMakefile}
# Using the "eval" to assign the Makefile's variable in the recipe
	@$(eval IsExisted	:=	$(shell grep -q "^Commons\.Sources\s*\(:\)\?=" "${TempMakefile}"  && echo "$$?"))
# Adding the variable into the file when the variables do not in the file, the information shall put into the file
	@if [ "${IsExisted}" != "0" ]; then \
		echo "Commons.Sources	:=	${projectDir}/Models/Commons/Sources" >> "${TempMakefile}"; \
	fi

# ######## [Compiling Items]
# Start time
startTime:
	@$(eval Duration := $(shell source ${projectDir}/Shells/compiledStringMessage.sh && echo $$(startingString "${Models}")))
# End Time
endTime:
	@echo $(shell source ${projectDir}/Shells/compiledStringMessage.sh && echo $$(endingString "${Models}" "${Duration}"))

# Commons.Time
${Commons.Sources}/Time.o:	${Commons.Sources}/Time.c
	${CC} ${STD} ${CMPOPT} ${DETAILINFO} ${WALL} ${CFLAGS} ${Commons.Sources}/Time.c -c ${FMSG} -o ${Commons.Sources}/Time.o

# Commons.EncodePrototype
${Commons.Sources}/EncodePrototype.o:	 ${Commons.Sources}/EncodePrototype.c
	${CC} ${STD} ${CMPOPT} ${DETAILINFO} ${WALL} ${CFLAGS} ${Commons.Sources}/EncodePrototype.c -c ${FMSG} -o ${Commons.Sources}/EncodePrototype.o

# Commons.EncodeBase64
${Commons.Sources}/EncodeBase64.o:	${Commons.Sources}/EncodeBase64.c
	${CC} ${STD} ${CMPOPT} ${DETAILINFO} ${WALL} ${CFLAGS} ${Commons.Sources}/EncodeBase64.c -c ${FMSG} -o ${Commons.Sources}/EncodeBase64.o