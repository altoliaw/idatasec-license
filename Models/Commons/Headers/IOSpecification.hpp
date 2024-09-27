#pragma once
/** @file IOSpecification.hpp
 * IO specifications; the class is used to migrate the output to the specified device
 * 
 * @note the code singleton is not proper for the unit test
 *
 * @author Nick, Liao
 * @date 2024/05/15
 */

#ifdef __linux__  // Linux

#include <unistd.h>

#include <iostream>

#include "./POSIXErrors.hpp"

namespace Commons {
/**
 * The IO specification; the object of the class is a singleton
 */
class IOSpecification {
   public:
    // For recording the current file descriptor
    int current;

    // For the output file descriptor
    int deviceID;

    ~IOSpecification();
    static IOSpecification* getSingleton();
    int migrateOutput(int, int);
    int recoverOutput();

   private:
    IOSpecification();
};

}  // namespace Commons
#endif