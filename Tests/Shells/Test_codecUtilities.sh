#!/bin/bash
# All tests are executed from the project root (i.e., the current working directory is the project root)
# Including the libraries
source $(pwd)/Shells/codecUtilities.sh

echo "==========================="

# Encoding
inputString="Hello"
echo "Original string: $inputString"
echo -n "Coverting to the ASCII values: "
encodedString=$(stringToAsciiHex "$inputString")
echo "$encodedString"

# Decoding
echo "==========================="
originalString=$(acsiiHexToString "$encodedString")
echo "Decoded string: $originalString"


