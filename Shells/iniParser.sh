#!/bin/bash
# /**
#  * Before executing the shell script, the files in the .ini folder shall be set.
#  * Please refer to the files mentioned above for setting.
#  *
#  * @author Nick
#  * @Date 2024/05/16
#  */

# /**
#  * Obtaining the value from the initiailization file (.ini) with a section name and the variable
#  *
#  * @param $0 The function called by users
#  * @param $1 The file name of the .ini file
#  * @param $2 The section denoted in .ini file
#  * @param $3 The key (variable) in the section ($2) denoted in .ini file
#  * @return The value of the key (variable) in the section ($2) denoted in .ini file
#  */
function getIniValue() {
	local fileName=$1
	local section=$2
	local key=$3
	awk -F '=' "/\[$section\]/ {f=1; next} /\[.*\]/{f=0} f && \$1 ~ /^[ \t]*$key[ \t]*$/ \
				{gsub(/^[ \t]*$key[ \t]*=[ \t]*/,\"\",\$0); print}" "$fileName" |
		sed 's/^[ \t]*//;s/[ \t]*$//'
}

# /**
#  * Obtaining the value from the initiailization file (.ini); all new keys are modelled in "section.old key"
#  *
#  * @param $0 The function called by users
#  * @param $1 The file name of the .ini file
#  * @param $2 The associated array as the buffer
#  * @return All values of the keys (variable) in all sections denoted in .ini file
#  */
function getIniValues() {
	local file="$1"
	local currentSection=""
	# Definition of the reference
	declare -n dictionary="$2"

	while IFS= read -r line || [ -n "$line" ]; do
		# Skipping the line if the starting symbol is a space, '#'
		if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
			continue
		fi

		# A new section if the starrting symbol is '['
		if [[ "${line:0:1}" == "[" && "${line: -1}" == "]" ]]; then
			currentSection="${line:1:-1}"
			continue
		fi

		# Key value pairs
		# "section.key" as a new key
		key="${currentSection}.${line%%=*}"
		# value
		value="${line#*=}"
		dictionary["$key"]="$value"
	done <"$file"
}

# /**
#  * Public Caller, obtaining the variable's value from the string; all variables are modelled in "section.old key"
#  *
#  * @param $0 The function called by users
#  * @param $1 The collected string from .ini file
#  * @param $2 The variable name
#  * @return The value of the variable
#  */
function getVariableValue() {
	local collectedString="$1"
	local variableName="$2"

	# Given the string to the awk, the value can be obtained by using match funciton with a regular expression
	echo $collectedString | awk "match(\$0, /$variableName=([^;]+);/, m) { print m[1] }"

}

#------

# /**
#  * Public Caller, obtaining the result
#  *
#  * @param $0 The function called by users
#  * @param $1 The file name of the .ini file
#  * @param $2 The variable name in the .ini file
#  * @return All values of the keys (variable) in all sections denoted in .ini file
#  */
function iniParser_getIni() {

	# Definition of the associated array
	declare -A result_dict
	getIniValues $1 result_dict

	# If there is no argument when calling to the function, the key and value pair will
	# be modelled as a string, and the delimiter is ';'
	if [ $# -eq 1 ]; then
		local tmp=""
		for key in "${!result_dict[@]}"; do
			printf '%s=%s;' "$key" "${result_dict[$key]}"
			# tmp+="$(printf '%s=%s;' "$key" "${result_dict[$key]}")"
		done

		# Printing the substring where the result is equal to the original string without the last word
		# echo "${tmp: 0:${#tmp} - 1}"
	else
		echo "${result_dict["$2"]}"
	fi
}
 