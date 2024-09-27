/**
 * @see StringImplement.hpp
 */
#include "../Headers/StringImplement.hpp"

namespace Commons {
/**
 * Obtaining the index of the first character from the string where the character is not a space;
 * the function may cause an error when the string is null/nullptr
 *
 * @param string [const unsigned char*] The input string
 * @param direction [const char] The direction for searching the string; 0x0 is from the left-hand
 * side and the 0x1 is the right-hand side (the default is 0)
 * @return [unsigned int] The index; if there is no character in the string, the value is equal to -1;
 * if the value is equal to -2, the error occurs
 */
int StringImplement::obtainFirstNotSpaceCharLocation(const unsigned char* string, const char direction) {
    int index = -2;  // Final result
    if(string != nullptr) {
        unsigned int stringLength = strlen((const char*)string);
        if (string != nullptr) {
            index = -1;
            if (direction == 0x0) {
                for (unsigned int i = 0; i < stringLength; i++) {
                    if (string[i] != ' ') {
                        index = (int)i;
                        break;
                    }
                }
            } else if (direction == 0x1) {
                for (unsigned int i = 0; i < stringLength; i++) {
                    if (string[stringLength - 1 - i] != ' ') {
                        index = (int)(stringLength - 1 - i);
                        break;
                    }
                }
            }
        }
    }
    return index;
}

/**
 *  Obtaining the string with no space(s) from the input string by
 *  trimming spaces from the left-hand side before the first non-space character
 *  of the input string
 *
 * @param string [unsigned char**] The address of the pointer of the string
 * @return [int] The length after trimming; if the value is equal to -1, the error occurs
 */
int StringImplement::trimLeftSpace(unsigned char** string) {
    int length = -1;
    // Searching from the left-hand side
    int index = StringImplement::obtainFirstNotSpaceCharLocation(*string);
    if (index >= -1 && index <= 0) {
        length = (int)strlen((const char*)(*string));
    } else if (index > 0) {
        length = (int)strlen((const char*)(*string)) - index;
        memmove(*string, (*string) + index, length);
        (*string)[length] = '\0';
    }
    return length;
}

/**
 *  Obtaining the string with no space(s) from the input string by
 *  trimming spaces from the right-hand side before the first non-space character
 *  of the input string
 *
 * @param string [unsigned char**] The address of the pointer of the string
 * @return [int] The length after trimming; if the value is equal to -1, the error occurs
 */
int StringImplement::trimRightSpace(unsigned char** string) {
    int length = -1;
    // Searching from the right-hand side
    int index = StringImplement::obtainFirstNotSpaceCharLocation(*string, (char)0x1);
    if (index >= -1 && index <= 0) {
        length = (int)strlen((const char*)(*string));
    } else if (index > 0) {
        length = index + 1;
        (*string)[length] = '\0';
    }
    return length;
}

/**
 *  Obtaining the string between the first character of the input string and the last character
 *  of the input string where all terms will be separated by a space at least;
 *  this function must be implemented after StringImplement::trimLeftSpace and
 *  StringImplement::trimRightSpace
 *
 * @param string [unsigned char**] The address of the pointer of the string
 * @return [int] The length after trimming; if the value is equal to -1, the error occurs
 */
int StringImplement::mergeRedundantSpace(unsigned char** string) {
    int length = -1;
    // Using the shifted concept which the string comes from the two substrings
    if (*string != nullptr) {
        int finalLength = (int)strlen((const char*)(*string));
        int checkedIndex = 0;
        for (unsigned int i = 0, j = 0; i < (unsigned int)finalLength; i++) {
            // When the pivot is a space and the previous checked character is a space as well,
            // the pivot shall be moved to the next one, and the checked character will be stayed in the
            // current index.
            j = ((checkedIndex == 0) ? 0 : (checkedIndex - 1));
            if ((*string)[i] == ' ' && (*string)[j] == ' ') {
                continue;
            }
            (*string)[j] = (*string)[i];
            checkedIndex++;
        }
        (*string)[checkedIndex] = '\0';
        length = (int)strlen((const char*)(*string));
    }
    return length;
}

/**
 *  Obtaining the string without the end character(s) is/are '\n' and '\r\n'
 * 
 * @param string [unsigned char**] The input string for verification
 * @return [int] The length of the string
 */
int StringImplement::obtainNoNewLineSignAtTheEnd(unsigned char** string) {
    int resultLength = 0;
    // When the string is null
    if(string == nullptr) {
        resultLength = 0;
    } else {
        int stringLength = (int) strlen((const char*)(*string));
        // If the length is larger than 2 and the last character is '\n'
        if(stringLength >= 2 && (*string)[stringLength - 1] == '\n') {
            if ((*string)[stringLength - 2] == '\r') {// When the last second character is '\r'
               (*string)[stringLength - 2] = (*string)[stringLength - 1] = '\0';
            } else { // If the length is larger than 1 and the last character is '\n'
                (*string)[stringLength - 1] = '\0';
            }
        } else if (stringLength >= 1 && (*string)[stringLength - 1] == '\n') {
            (*string)[stringLength - 1] = '\0';
        }
        else {
            // Doing nothing
        }
        resultLength = (int) strlen((const char*)(*string));
    }

    return resultLength;
}
};  // namespace Commons