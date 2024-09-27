#pragma once
/** @file HashTable.hpp
 * The class of the hash table
 *
 * @author Nick, Liao
 * @date 2024/05/24
 */
#include <string.h>

#include <iostream>

#include "./POSIXErrors.hpp"

namespace Commons {
/**
 * The hash table (Some customers have old platforms; that implies users
 * can not use container in C++)
 */
class HashTable {
   public:
    /**
     * For the reserving the type of the value in the struct "Element"
     */
    enum ElementType {
        charType = 0,
        unsignedCharType,
        integerType,
        floatType,
        doubleType,
        stringType,
        charStarType,
        unsignedCharStarType,
        fileStarType,
        OtherType,
    };

    /**
     * The element for the hash table
     */
    struct Element {
        // The column name
        char* columnName;
        // The value of the column name
        void* value;
        // The next address of the element for linking with the hash table
        Element* nextInHashTable;
        // The size of the memory for reserving the variable, value
        size_t sizeOfMemory;
        // Reserving the original type of the value
        ElementType type;

        // The next address of the element in queuing for
        // the situation when all elements will be removed
        Element* nextInQueue;
        // The next address of the element in queuing for
        // the situation when all elements will be removed (easily maintain the structure in the queue)
        Element* previousInQueue;
        Element(const char*, void*, size_t, ElementType = ElementType::charStarType);
        ~Element();
    };

    // The size of the size of the hash table
    unsigned int hashTableSize;
    // The pointer to the hash table (array), and each element in the table is an element
    Element** hashTable;
    // A queue for reserving all elements in the hash table;
    // this is a mechanism for fast releasing memory
    Element* queue;
    // The address of the last element in the queue
    Element* lastElement;
    // The element pointer to the new/updating element when "addElementIntoHashTable(.)/getValueByName(.)" executes
    Element* operatedElement;


    HashTable(int = 97);
    virtual ~HashTable();
    virtual char getValueByName(char*, char**, void**, size_t*, ElementType*);
    virtual POSIXErrors removeElementByName(char*);
    virtual POSIXErrors addElementIntoHashTable(char*, void*, size_t, ElementType = ElementType::charStarType);

   protected:
    virtual unsigned int getHashIndex(char*);
};

}  // namespace Commons