/**
 * @see IOSpecification.hpp
 */
#include "../Headers/IOSpecification.hpp"
#ifdef __linux__
namespace Commons {
/**
 * Constructor
 */
IOSpecification::IOSpecification() {
    // The field IS initialized in the error mode
    current = -1;
}

/**
 * Destructor
 */
IOSpecification::~IOSpecification() {
    // The field is initialized in the error mode
    current = -1;

    // The migration flag
    if (deviceID >= 0) {
        IOSpecification::recoverOutput();
    }
    deviceID = -1;
}

/**
 * The function for obtaining the singleton object;
 * using the feature where the static variable in the function
 *
 * @return [IOSpecification*] The address of the object created by class, IOSpecification
 */
IOSpecification* IOSpecification::getSingleton() {
    // Creating a static object when the function executes in the first time
    static IOSpecification instance;
    return &instance;
}

/**
 * Setting the file descriptor to the device ID
 *
 * @param deviceID [int] The device from the standard device (e.g., stderr or stdout ID)
 * @param fileDescriptor [int] The output descriptor ID
 *
 * @return [int] The state defines in the POSIXErrors.hpp
 */
int IOSpecification::migrateOutput(int deviceID, int fileDescriptor) {
    if (deviceID < 0 || fileDescriptor < 0) {
        std::cerr << "\"deviceID | fileDescriptor\" error";
        return Commons::POSIXErrors::E_BADF;
    }
    this->deviceID = deviceID;
    current = dup(deviceID);
    if (dup2(fileDescriptor, deviceID) < 0) {
        std::cerr << "\"deviceID\" redirection failed";
        return Commons::POSIXErrors::E_BADF;
    }
    return Commons::POSIXErrors::OK;
}

/**
 * Recovering the descriptor to the original one
 *
 * @return [int] The state defines in the POSIXErrors.hpp
 */
int IOSpecification::recoverOutput() {
    if(dup2(current, deviceID) < 0) {
    	std::cerr << "\"fileDescriptor\" redirection failed";
    	return Commons::POSIXErrors::E_BADF;
    }
    return Commons::POSIXErrors::OK;
}

}  // namespace Commons
#endif