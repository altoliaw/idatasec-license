#pragma once
/** @file StringImplement.hpp
 * Any type string implementation, for example, trimming
 *
 * @author Nick, Liao
 * @date 2024/05/15
 */

#include <iostream>
#include <string.h>
#include <string>

#include "./POSIXErrors.hpp"

namespace Commons {
/**
 * Several string implementation
 */
class StringImplement {
   public:
    static int obtainFirstNotSpaceCharLocation(const unsigned char*, const char = 0x0);
	static int trimLeftSpace(unsigned char**);
    static int trimRightSpace(unsigned char**);
	static int mergeRedundantSpace(unsigned char**);
    static int obtainNoNewLineSignAtTheEnd(unsigned char**);
};

}  // namespace Commons