#pragma once
/** @file Log.hpp
 * Log information operation; the log is modeled as a hash table, the default key of the log
 * is default
 *
 * @author Nick, Liao
 * @date 2024/06/13
 */

#include <iostream>
#include <unordered_map> // For the reserved file descriptors, accepted since C++11, a fast dictionary in C++ without the hand-made coding

#include "./POSIXErrors.hpp"
#include "./HashTable.hpp"
namespace Commons {
/**
 * A log class, the class is a static class and is modeled in a singleton
 */
class Log {
   public:
    // A log file will refer to a hash table because users can generate different logs flexibly.
    static HashTable* logTablePointer;
    // A unordered map pointer refers to an unordered map for recording the map where the
    // key value pairs are log abbreviated names and file descriptors; the key shall not be released memory manually when the element 
    // will be erased because the key's memory is from the key of the hash table; as a result the pointer shall be deleted before the
    // pointer, logTablePointer 
    static std::unordered_map<const char*, FILE*>* logMapPointer;
    // The variable will be located in the static area in the memory and initialized once
    // when the variable executes at the first time
    static FILE* currentLog;  
                                        

	static void getHashTableInitialization();
	static char setLogTableInformation(void*, size_t, HashTable::ElementType = HashTable::ElementType::charStarType, const char* = "default", char = 0x1);
	static void executeLog(std::ostream&, const char*, POSIXSysLog = POSIXSysLog::Debug, const char* = "default");
	static char getLogTableInformation(char**, void**, size_t*, HashTable::ElementType*, const char* = "default");
    static char open(const char*, const char* = "default", const char* = "logs/.log");
    static char close(const char* = "default");
    static char closeAll();

   private:
    Log();
};

}  // namespace Commons