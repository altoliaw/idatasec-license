/**
 * @see Log.hpp
 */
#include "../Headers/Log.hpp"

namespace Commons {
// The definition of the static variables of the class
HashTable* Log::logTablePointer = nullptr;
std::unordered_map<const char*, FILE*>* Log::logMapPointer = nullptr;
FILE* Log::currentLog = nullptr;

/**
 * The function is the first method when using static methods in this class; all
 * variables in the class will be initialized; the function has been called by other static functions
 * in this class; as a result, users do not call the function in the codes
 */
void Log::getHashTableInitialization() {
    // For reserving the paths of the logs with abbreviated log names
    static HashTable hashTable;  // The constructor will be executed automatically
    if (Log::logTablePointer == nullptr) {
        Log::logTablePointer = &hashTable;  // Static singleton
    }

    // For reserving the file descriptors of the logs with abbreviated log names
    static std::unordered_map<const char*, FILE*> logMap;  // The constructor will be executed automatically
    if (Log::logMapPointer == nullptr) {
        Log::logMapPointer = &logMap;
    }
}

/**
 * Setting the log information into the hash table; that implies the log path will be set in
 * the hash table
 *
 * @param value [void*] The log file name (char*) and shall be cast into the void* because of a general solution
 * @param sizeOfMemory [size_t] The size of the memory of the value above
 * @param type [HashTable::ElementType] The type of the value above; the default value is "HashTable::ElementType::charStarType"
 * @param abbreviatedLogName [const char*] The abbreviation of the log name; the default value is "default"
 * @param isReassignment [char] The flag for determining if the value shall be reassigned when the element has existed in the hash table;
 * when the value is equal to 0x0, the value will not be reassigned in the element when the element exists;
 * when the value is equal to 0x1, the value will be reassigned in the element when the element exists;
 * the default value is 0x1; this parameter is for further custom extension
 * @return [char] The flag if the function works well; if the function is okay, the value is 0x1; otherwise 0x0 (error occurs)
 */
char Log::setLogTableInformation(void* value, size_t sizeOfMemory, HashTable::ElementType type, const char* abbreviatedLogName, char isReassignment) {
    // Initialization automatically if the pointer is equal to nullptr
    Log::getHashTableInitialization();

    char isSuccess = 0x0;
    char isExisted = 0x0;
    void* tmpValue = nullptr;  // The address which refers to the value object

    HashTable::ElementType tmpType = HashTable::ElementType::charStarType;
    size_t tmpMemorySize = 0;

    char* columnNameAddressInHash = nullptr;
    // Verifying if the existence of the element
    isExisted = (Log::logTablePointer)->getValueByName((char*)abbreviatedLogName, &columnNameAddressInHash, &tmpValue, &tmpMemorySize, &tmpType);
    if (isExisted == 0x0) {  // The element does not exist, calling the function, HashTable::addElementIntoHashTable(.)
        (Log::logTablePointer)->addElementIntoHashTable((char*)abbreviatedLogName, value, sizeOfMemory);
        isSuccess = 0x1;
    } else {                            // When the element exists, ...
        if (isReassignment == 0x1) {    // The situation where the element exists and the flag is 0x1
            if (tmpValue == nullptr) {  // The element exists and the value is nullptr.
                // "calloc" method
                tmpValue = calloc(1, sizeOfMemory);
            } else {
                // "realloc" method
                tmpValue = realloc(tmpValue, sizeOfMemory);
            }
            // When the dynamic allocation has been success, the log table has been set
            if (tmpValue != nullptr) {
                isSuccess = 0x1;
                memcpy(tmpValue, value, sizeOfMemory);
            }
        }
    }
    return isSuccess;
}

/**
 *
 */
void Log::executeLog(std::ostream&, const char*, POSIXSysLog = POSIXSysLog::Debug, const char* = "default") {
}

/**
 * Obtaining the log information from the hash table; that implies the log path
 *
 * @param columnNameAddressInHash [char**] The address of the column name with physical memory space in the hash
 * where the column name is equal to columnNameAddressInHash; the physical memory space will be released when the destructor of the hash table is called
 * @param value [void**] The address of the pointer of the value (FILE*)
 * @param sizeOfMemory [size_t*] The size of the memory of the value above
 * @param type [HashTable::ElementType*] The address of the HashTable::ElementType and the type implies the
 * original type of the value
 * @param abbreviatedLogName [const char*] The key in the hash table, the default value is "default"
 * @return [char] The successful flag; when the flag is 0x1, the function is okay; otherwise, the function error occurs
 */
char Log::getLogTableInformation(char** columnNameAddressInHash, void** value, size_t* sizeOfMemory, HashTable::ElementType* type, const char* abbreviatedLogName) {
    char isExisted = 0x0;

    // Verifying if the existence of the element
    isExisted = (Log::logTablePointer)->getValueByName((char*)abbreviatedLogName, columnNameAddressInHash, value, sizeOfMemory, type);
    return isExisted;
}

/**
 * Opening the specified log with the specified mode
 *
 * @param mode [const char*] The mode when using fopen(.)
 * @param abbreviatedLogName [const char*] The name denoted in the hash table for the log (the default value is "default")
 * @return [char] The flag if the function works well; if the function is okay, the value is 0x1; otherwise 0x0 (error occurs)
 */
char open(const char* mode, const char* abbreviatedLogName, const char* logPath) {
    // Preparing the useless arguments because the parameters in the f(.) require memory spaces
    char* columnNameAddressInHash = nullptr;
    void* value = nullptr;
    size_t sizeOfMemory = 0;
    HashTable::ElementType type = HashTable::ElementType::charStarType;

    // The success flag
    char isSuccess = 0x0;
    isSuccess = Log::getLogTableInformation(&columnNameAddressInHash, &value, &sizeOfMemory, &type, abbreviatedLogName);
    if (isSuccess == 0x1 && type == HashTable::ElementType::charStarType) {
        Log::currentLog = fopen((char*)value, mode);
        isSuccess &= (Log::currentLog == nullptr) ? 0x0 : 0x1;

        // Carrying the static file pointer with the static member in the class
        std::unordered_map<const char*, FILE*>::iterator it = (Log::logMapPointer)->find(abbreviatedLogName);
        if (it == (Log::logMapPointer)->end()) {  // No hitting the element in the map, the file descriptor shall be added into the unordered map

            (Log::logMapPointer)->insert(std::make_pair<const char*>((const char*)columnNameAddressInHash, Log::currentLog));

        } else {                          // Hitting; the close function shall be called in advance and the element in the unordered map shall be updated
            if (it->second != nullptr) {  // Closing the current one from the element in the unordered map
                fclose(it->second);
                it->second = nullptr;
            }
            it->second = Log::currentLog;  // Updating the element's value
        }
    } else if (isSuccess == 0) {  // If there is no path, the path shall be put into the hash table
                                  // and the file descriptor shall be opened
        // Setting the values into the hash table (path information)
        value = (void*)logPath;
        sizeOfMemory = strlen(logPath);
        char isReassignment = 0x1;  // Setting the value forcedly if the element in the table exists
        Log::setLogTableInformation(value, sizeOfMemory, type, abbreviatedLogName, isReassignment);
        // Assigned the key address in the hash table by re-searched function; the time complexity is O(1)
        isSuccess |= Log::getLogTableInformation(&columnNameAddressInHash, &value, &sizeOfMemory, &type, abbreviatedLogName);  // The previous value of "isSuccess" is 0.

        // Setting the file descriptor into the unordered map
        if (isSuccess == 0x1) {
            Log::currentLog = fopen((char*)value, mode);
            isSuccess &= (Log::currentLog == nullptr) ? 0x0 : 0x1;

            // Carrying the static file pointer with the static member in the class
            std::unordered_map<const char*, FILE*>::iterator it = (Log::logMapPointer)->find(abbreviatedLogName);
            if (it == (Log::logMapPointer)->end()) {  // No hitting the element in the map, the file descriptor shall be added into the unordered map

                (Log::logMapPointer)->insert(std::make_pair<const char*>((const char*)columnNameAddressInHash, Log::currentLog));

            } else {                          // Hitting; the close function shall be called in advance and the element in the unordered map shall be updated
                if (it->second != nullptr) {  // Closing the current one from the element in the unordered map
                    fclose(it->second);
                    it->second = nullptr;
                }
                it->second = Log::currentLog;  // Updating the element's value
            }
        }
    }

    return isSuccess;
}

/**
 * Closing the specified log from the unordered map
 *
 * @param abbreviatedLogName [const char*] The name denoted in the hash table for the log (the default value is "default")
 * @return [char] The flag if the function works well; if the function is okay, the value is 0x1; otherwise 0x0 (error occurs)
 */
char Log::close(const char* abbreviatedLogName) {
    char isSuccess = 0x0;

    std::unordered_map<const char*, FILE*>::iterator it = (Log::logMapPointer)->find(abbreviatedLogName);
    if (it != (Log::logMapPointer)->end()) {  // Hitting the element in the map, the file descriptor shall be closed and erasing the element
        if (it->second != nullptr) {          // Closing the current one from the element in the unordered map
            fclose(it->second);               // Closing the file descriptor
            it->second = nullptr;
        }
        (Log::logMapPointer)->erase(abbreviatedLogName);  // Erasing the element
        isSuccess = 0x1;
    }
    return isSuccess;
}

/**
 * Closing all logs from the unordered map
 *
 * @return [char] The flag if the function works well; if the function is okay, the value is 0x1; otherwise 0x0 (error occurs)
 */
char Log::closeAll() {
    char isSuccess = 0x0;

    for (std::unordered_map<const char*, FILE*>::iterator it = (Log::logMapPointer)->begin(); it != (Log::logMapPointer)->end(); it++) {
        if (it->second != nullptr) {  // Closing the current one from the element in the unordered map
            fclose(it->second);       // Closing the file descriptor
            it->second = nullptr;
        }
    }
    // Removing all elements from the unordered map
    (Log::logMapPointer)->clear(); // The unordered map will execute the destructor
    (Log::logMapPointer) = nullptr;
    return isSuccess;
}

}  // namespace Commons