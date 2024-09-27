#!/bin/bash

# /**
#  * Converting each character in the string to a series of 2-byte hexadecimal ASCII values
#  *
#  * @param $0 The function called by users
#  * @param $1 The input string
#  * @return All values of the keys (variable) in all sections denoted in .ini file
#  */
stringToAsciiHex() {
    local input="$1"
    local output=""
    local i

    for (( i =0; i < ${#input}; i++ )); do
        # Converting each character in the string to a series of 2-byte hexadecimal ASCII values
        output+=$(printf "%02x" "'${input:$i:1}")
    done

    echo "${output}"
}

# /**
#  * Converting a series of 2-byte hexadecimal ASCII values back to the original string
#  *
#  * @param $0 The function called by users
#  * @param $1 The input hexadecimal string
#  * @return The original string
#  */
acsiiHexToString() {
    local input="$1"
    local output=""
    local i=0
	local hex=0


	for (( i =0; i < ${#input}; i+=2 )); do
        # Converting each character in the string to a series of 2-byte hexadecimal ASCII values
        hex="${input:$i:2}"
        output+=$(printf "\\x$hex")
    done

    echo "$output"
}