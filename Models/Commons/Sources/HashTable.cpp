/**
 * @see HashTable.hpp
 */
#include "../Headers/HashTable.hpp"

namespace Commons {

/**
 * Constructor
 *
 * @param size [int] The size of the hashtable, the default value
 * is 97 (a prime); if possible, the value of the size shall be set as a prime
 */
HashTable::HashTable(int size) {
    hashTableSize = size;
    queue = lastElement = operatedElement = nullptr;
    hashTable = new Element* [hashTableSize] {}; // Setting nullptr to all elements
}

/**
 * Destructor
 */
HashTable::~HashTable() {
    // Releasing all objects from the queue
    Element* current = nullptr;

    // Traversal all objects in the queued linked list
    for (; queue != nullptr;) {
        current = queue;
        queue = queue->nextInQueue;
        // Releasing the element's memory
        delete current;
        current = nullptr;
    }
    queue = nullptr;
    lastElement = nullptr;

    // Because all elements have been removed from queue,
    // the hash table can be removed directly
    if (hashTable != nullptr) {
        delete[] hashTable;
    }
    hashTable = nullptr;
    hashTableSize = 0;
    operatedElement = nullptr;
}

/**
 * Constructor of the element
 *
 * @param columnName [char*] The column name
 * @param value [char*] The value of the column
 * @param sizeOfMemory [size_t] The size of memory of the value above
 * @param type [ElementType] The original type of the value defined above; the default type is "charStarType" (char*)
 */
HashTable::Element::Element(const char* columnName, void* value, size_t sizeOfMemory, ElementType type) {
    this->columnName = (char*)columnName;
    this->value = value;
    this->sizeOfMemory = sizeOfMemory;
    this->type = type;

    nextInHashTable = nullptr;
    nextInQueue = nullptr;
    previousInQueue = nullptr;
}

/**
 * Destructor of the element
 */
HashTable::Element::~Element() {
    // Removing the memories for the "char" arrays
    if (columnName != nullptr) {
        delete[] columnName;
        columnName = nullptr;
    }
    if (value != nullptr) {
        free(value);
        value = nullptr;
    }
    this->sizeOfMemory = 0;
    this->type = ElementType::charStarType;

    nextInQueue = nullptr;
    previousInQueue = nullptr;
    nextInHashTable = nullptr;
}

/**
 * Obtaining the result from the hash table
 *
 * @param columnName [char*] The column name
 * @param columnNameInHashAddress [char**] The copied column name from the element in the hash (the pointer can be reused from the caller)
 * @param value [void**] The address of the value of the column name
 * @param sizeOfMemory [size_t*] The address of the size of memory of the value; using the
 * memory to obtain the memory from the caller
 * @param type [ElementType*] The pointer to the type from the caller
 * @return [char] The number of the hit element; if the element does not exist,
 * the value will be 0x0; otherwise 0x1
 */
char HashTable::getValueByName(char* columnName, char** columnNameInHashAddress, void** value, size_t* sizeOfMemory, ElementType* type) {
    char result = 0x0;
    if (columnName == nullptr) {
        return result;
    }

    unsigned int index = getHashIndex(columnName);
    Element* current = hashTable[index];
    for (; current != nullptr;) {
        if (strcmp(current->columnName, columnName) != 0) {  // If the two strings are not equal, ...
            current = current->nextInHashTable;
        } else {
            result = 0x1;
            operatedElement = current; // Passing the hitting element address to the pointer, operatedElement
            *columnNameInHashAddress = current->columnName;
            *value = current->value;
            *sizeOfMemory = current->sizeOfMemory;
            *type = current->type;
            break;
        }
    }

    return result;
}

/**
 * Removing the element by using the specific name
 *
 * @param columnName [char*] The name of the column
 * @return [POSIXErrors] The success/fail value*
 */
POSIXErrors HashTable::removeElementByName(char* columnName) {
    if (columnName == nullptr) {
        return POSIXErrors::E_NOITEM;
    }

    Element* removedItem = nullptr;

    unsigned int index = getHashIndex(columnName);
    Element* current = hashTable[index];
    Element* previous = nullptr;
    for (; current != nullptr;) {
        if (strcmp(current->columnName, columnName) != 0) {  // If the two string are not equal, ...
            previous = current;
            current = current->nextInHashTable;
        } else {
            removedItem = current;
            // If the current one address is equal to the removed one
            if (operatedElement == removedItem) {
                operatedElement = nullptr;
            }
            break;
        }
    }

    // If there exists nothing in the hash table with linked lists, ...
    if (removedItem == nullptr) {
        return POSIXErrors::E_NOITEM;

    } else {  // Hitting the element
        // Maintaining the linked list from the hash table (single direction)
        if (previous == nullptr && removedItem->nextInHashTable == nullptr) {  // There is only one element in the linked list
                                                                               // and the one is the removedItem
            hashTable[index] = nullptr;
        } else if (previous == nullptr && removedItem->nextInHashTable != nullptr) {  // The first element is the removedItem
                                                                                      // in the linked list.
            hashTable[index] = removedItem->nextInHashTable;
        } else if (previous != nullptr && removedItem->nextInHashTable == nullptr) {  // The last element is the removedItem.
                                                                                      // in the linked list
            previous->nextInHashTable = nullptr;
        } else {
            previous->nextInHashTable = removedItem->nextInHashTable;
        }
    }

    // Maintaining the queue (bi-direction)
    previous = removedItem->previousInQueue;
    Element* next = removedItem->nextInQueue;
    if (previous == nullptr) {
        if (next == nullptr) {
            // In the linked listed, there exist an element, namely removedItem. As
            // as result the queue pointer shall be set as nullptr
            queue = nullptr;
        } else {  // The previousInQueue of the next element shall be modified as nullptr
            next->previousInQueue = nullptr;
            queue = next;
        }
    } else {  // If there exist an element before the removedItem, ...
        if (next == nullptr) {
            // The nextInQueue of the previous element shall be modified as nullptr
            previous->nextInQueue = nullptr;
        } else {
            // The nextInQueue of the previous element shall be modified as the next element and
            // the previousInQueue of the next element shall be modified as the previous element
            previous->nextInQueue = next;
            next->previousInQueue = previous;
        }
    }

    // Deleting the removedItem
    delete removedItem;
    return POSIXErrors::OK;
}

/**
 * Adding an element, and putting the element into the hash table with linked lists
 *
 * @param columnName [char*] The name of the column
 * @param value [char*] The value of the column
 * @param sizeOfMemory [size_t] The size of memory of the value above
 * @param type [ElementType] The original type of the value defined above; the default type is "charStarType" (char*)
 * @return [POSIXErrors] The success/fail value
 */
POSIXErrors HashTable::addElementIntoHashTable(char* columnName, void* value, size_t sizeOfMemory, ElementType type) {
    if (columnName == nullptr) {
        return POSIXErrors::E_NOITEM;
    }

    // Copying the strings, "\0" will be added at the last character automatically
    char* tmpColumnName = new char[strlen(columnName) + 1];
    strcpy(tmpColumnName, columnName);

    void* tmpValue = (value == nullptr) ? nullptr : calloc(1, sizeOfMemory);
    memcpy(tmpValue, value, sizeOfMemory);

    // Creating an element instance by using dynamic memory allocation
    Element* instance = new Element(tmpColumnName, tmpValue, sizeOfMemory, type);  // Initialization
    operatedElement = instance;
    
    if (instance == nullptr) {
        return POSIXErrors::E_NOMEM;
    }

    // Registering the element into the queue
    if (queue == nullptr) {
        queue = lastElement = instance;
    } else {
        lastElement->nextInQueue = instance;
        instance->previousInQueue = lastElement;
        lastElement = instance;
    }

    // Setting the element into the hash table
    unsigned int index = getHashIndex(instance->columnName);
    Element* current = nullptr;
    if (hashTable[index] != nullptr) {
        
        // Looping to the end element of the linked list
        for (current = hashTable[index]; current->nextInHashTable != nullptr; current = current->nextInHashTable) {
        }
        // Linking the new element and the last element in the linked list
        current->nextInHashTable = instance;
    } else {
        hashTable[index] = instance;
    }

    return POSIXErrors::OK;
}

/**
 * Obtaining the index from the name
 *
 * @param columnName [char*] The starting address of the name string
 * @return [unsigned int] The index for tha hash table
 */
unsigned int HashTable::getHashIndex(char* columnName) {
    unsigned int index = 0;
    for (unsigned int i = 0; i < strlen(columnName); i++) {
        index += (unsigned int)columnName[i];
    }
    index %= hashTableSize;
    return index;
}

};  // namespace Commons