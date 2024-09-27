#!/bin/bash

# /**
#  * Showing the upcoming process information
#  *
#  * @param $0 The function called by users
#  * @param $1 The target process
#  * @return The starting date
#  */
startingString() {
    # Process name
    local targetProcess="$1"
    # Start time
	local startDate=$(date +%s);

    local message="================================================================================================\n"
    message+="Process: $targetProcess \t Starting time: $startDate\n"
    echo -e "\033[34m$message\033[0m" >&2 
    echo "$startDate"
}

# /**
#  * Showing the process information when the end of the process
#  *
#  * @param $0 The function called by users
#  * @param $1 The target process
#  * @param $2 The starting date
#  */
endingString() {
    # Process name
    local targetProcess="$1"
    # Start time
    local startDate=$2;
    
    # End time
	local endDate=$(date +%s);
    local duration=$((endDate - startDate))

    local message="End time: $endDate\n"
    message+="Process: $targetProcess \t Duration: $duration sec(s)\n"
    message+="================================================================================================"
    
    # Printing the message
    echo -e "\033[34m$message\033[0m" >&2 
    # Returning the value
    echo "$output"
}