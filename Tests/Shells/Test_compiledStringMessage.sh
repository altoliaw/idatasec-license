#!/bin/bash
# All tests are executed from the project root (i.e., the current working directory is the project root)
# Including the libraries
source $(pwd)/Shells/compiledStringMessage.sh

startDate=$(startingString "main.o")

endingString "main.o" "$startDate"