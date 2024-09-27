#!/bin/bash
# /**
#  * Public Caller, making the version
#  *
#  * @param $0 The function called by users
#  * @param $1 The file name of the .version file
#  * @param $2 The version string
#  * @param $3 The parameter for determining when users feel like
#  * adding one to the major, minor or patch; one "#" implies that the number of
#  * "patch" will be changed; two "#" (i.e., "##") imply that the patch number will be set
#  * to 0 and the minor number will be plused 1; the three "#" (i.e., "###")
#  * imply that the patch and minor numbers will be set to 0 and the major number
#  * will be plused 1
#  */
function makeVersion() {
	local versionFile="$1"
	local versionTmpFile="$versionFile.tmp"
	local versionString="$2"
	local instruction="$3"

	# Obtaining the first token before the character "."
	local sectionString=$(echo "$versionString" | awk -F '[][]' '/\[.*\]/ {print $2}')
	# Obtaining the token between the characters "." and "="
	local variable=$(echo "$versionString" | awk -F '=' '!/\[.*\]/ {print $1}')
	# Obtianing the token after the character "="
	local version=$(echo "$versionString" | awk -F '=' '!/\[.*\]/ {print $2}')

	# Obtaining the major, minor and patch
	local major=$(echo "$version" | awk -F '.' '{print $1}')
	local minor=$(echo "$version" | awk -F '.' '{print $2}')
	local patch=$(echo "$version" | awk -F '.' '{print $3}')

	# Obtaining the length of the instruction
	local length=${#instruction}

	# Major, minor and patch rules
	# When the length =1 and the value is '#' or the length of the instruction is zero, ...
	if ([ "$length" = "1" ] && [ "$instruction" = '#' ]) || [ -z "$instruction" ]; then
		# The patch number will be + 1.
		patch=$((patch + 1))
	elif [ "$length" = "2" ] && [ "$instruction" = '##' ]; then
		patch="0"
		minor=$((minor + 1))
	elif [ "$length" = "3" ] && [ "$instruction" = '###' ]; then
		patch="0"
		minor="0"
		major=$((major + 1))
	fi

	# The project name
	projectName=$(basename "$PWD")

	# Git information
	gitInstalled=$(command -v git 2>/dev/null)
	gitHash="None"
	copyRightDate=$(date +"%Y%m%d.%H%M")

	# If the git has been installed, the short committed hash value will be obtained.
	if [ ! -z "$gitInstalled" ]; then
		# Obtaining git hash value
		gitHash=$(git rev-parse --short HEAD)
	else
		exit 1
	fi

	# File name is shown as below.
	fileName="$projectName.$major.$minor.$patch.$copyRightDate.$(uname)$(uname -r).GIT$gitHash"

	# Making a folder in the project
	mkdir -p "$projectName"
	cp -ar Settings ./"$projectName"
	cp -ar Bin ./"$projectName"
	cp -ar Outputs ./"$projectName"
	tar zcvf "$fileName.tar.gz" "$projectName"

	# Version migration
	cp -pr "$versionFile" "$versionTmpFile"
	content="[$sectionString]\n$variable=$major.$minor.$patch"
	# Printing the content into the .tmp
	echo -e "$content" > "$versionTmpFile"
	mv "$versionTmpFile" "$versionFile"
	rm -rf "$projectName"
}