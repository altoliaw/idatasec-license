/**
 * @see License.h
 */
#include "../Headers/Time.h"

static void getTimeInitialization(Time*);
static long getEpoch(Time*, time_t);
static long getStringToEpoch(Time*, const char*);
static void releaseInitializedFileParserInitialization(Time*);
static void getEpochToString(Time*, const char*, Timezone, long, unsigned char**);

/**
 * Constructor of Time class
 * 
 * @param instance [Time*] The instance
 */
 void Time_Construct(Time* instance) {
    instance->timeEpochPointer = NULL;

    // Function pointers's definitions
    instance->getEpoch = &getEpoch;
    instance->getStringToEpoch = &getStringToEpoch;
    instance->releaseInitializedFileParserInitialization = &releaseInitializedFileParserInitialization;
    instance->getEpochToString = &getEpochToString;
 }

/**
 * Destructor of Time class
 * 
 * @param instance [Time*] The instance
 */
 void Time_Destruct(Time* instance) {
    instance->timeEpochPointer = NULL;

    // Function pointers's definitions
    instance->getEpoch = NULL;
    instance->getStringToEpoch = NULL;
    instance->releaseInitializedFileParserInitialization = NULL;
    instance->getEpochToString = NULL;
 }

/**
 * Time object initialization
 * 
 * @param instance [Time*] The instance of the Time class
 */
static void getTimeInitialization(Time* instance) {
    time_t now = time(NULL);
    // The timeEpoch variable depends on the function and is static.
    static long timeEpoch = 0;
    if (timeEpoch <= 0) {
        timeEpoch = (now <= -1) ? (long)-1 : (long)now;
    }

    // Referring the static variable to the static field in class if the static field is nullptr
    if (instance->timeEpochPointer == NULL) {
        instance->timeEpochPointer = &timeEpoch;
    }
}

/**
 * The time for obtaining the epoch
 *
 * @param instance [Time*] The instance of the Time class
 * @param timeInstance [time_t] The time value; the default value is the current time when the variable is equal to 0; please verifying the
 * setting in the declaration
 * @return [long] The epoch; if the value is -1, the error occurs
 */
static long getEpoch(Time* instance, time_t timeInstance) {
    // Initialization automatically if the pointer is equal to NULL
    getTimeInitialization(instance);

    // Reserving the value of the parameter into the static variable in the function, getTimeInitialization
    if (timeInstance == 0) {
        time_t now = time(NULL);
        timeInstance =  (now <= -1) ? (long)-1 : (long)now;
    }

    *(instance->timeEpochPointer) = timeInstance;
    return *(instance->timeEpochPointer);
}


/**
 * Transforming the POSIX ("%Y-%m-%d %H:%M:%S") time string into the epoch from OS time setting
 *
 * @param instance [Time*] The instance of the Time class
 * @param timeString [const char*] The time string (e.g., "2024-06-07 15:30:00")
 * @return [long] The epoch; if the value is -1, the error occurs
 */
static long getStringToEpoch(Time* instance, const char* timeString) {
    // Initialization automatically if the pointer is equal to nullptr
    getTimeInitialization(instance);

    // ISO C "broken-down" time structure
    struct tm tm;
    memset(&tm, 0, sizeof(tm));

    // Parsing the string into the tm object
    if (strptime(timeString, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        fprintf(stderr, "Failed to parse date string\n");
        return -1;
    }

    // Putting the time by using the mktime and reserving the value into the static variable from the
    // function, getTimeInitialization
    *(instance->timeEpochPointer) = (long)mktime(&tm);

    // Determining if the OS time is on the summer/daylight time
    if (tm.tm_isdst == 1) {
        *(instance->timeEpochPointer) -= 3600;  // -1 hour
    }

    return *(instance->timeEpochPointer);
}

/**
 * Obtaining the time string by transforming the unix timestamp with the users specified; that implies that a UTC timestamp
 * will be transformed into the specified time string in the specified zone
 *
 * @param instance [Time*] The pointer to the time instance
 * @param format [const char*] The layout format presented by using POSIX time format ("%Y-%m-%d %H:%M:%S")
 * @param zone [TimeZone] The time zone defined in the enumeration
 * @param timeEpoch [long] The epoch which users define for transforming to the time string;
 * the default value is from the static variable in the function, getTimeInitialization
 * @param timeEpochString [unsigned char**] The string of the time epoch; the variable shall be released manually from the caller
 * @return [unsigned char*] The time string
 */
static void getEpochToString(Time* instance, const char* format, Timezone zone, long timeEpoch, unsigned char** timeEpochString) {
    // Initialization automatically if the pointer is equal to nullptr
    getTimeInitialization(instance);

    // The pointer of the ISO C "broken-down" time structure
    struct tm* tm;
    time_t tmpTimeEpoch = 0;

    // Setting the new time zone
    switch (zone) {
        case LOCAL: // The local time
            tmpTimeEpoch = (time_t)timeEpoch;
            tm = localtime(&tmpTimeEpoch);
            break;

        case UTC:
        case GMT:
            tmpTimeEpoch = (time_t)timeEpoch;
            tm = gmtime(&tmpTimeEpoch);
            break;

        case PST:
            // The offset between the PST and UTC is 8 hours. In addition, the offset of the PST is -8
            tmpTimeEpoch = (time_t)timeEpoch - 8 * 3600;
            tm = localtime(&tmpTimeEpoch);
            break;

        case NST:
            // The offset between the PST and UTC is 3.5 hours. In addition, the offset of the PST is -3 hours and 30 mins
            tmpTimeEpoch = (time_t)timeEpoch - 3 * 3600 - (30 * 60);
            tm = localtime(&tmpTimeEpoch);
            break;

        default:  // Using the local time
            tmpTimeEpoch = (time_t)timeEpoch;
            tm = localtime(&tmpTimeEpoch);
    }

    // Copying the time string into the buffer
    int length = (int)strlen(format) * 4;
    if (*timeEpochString == NULL) {
        *timeEpochString = calloc(length , sizeof(unsigned char));
        (*timeEpochString)[0] = '\0';
    }

     strftime(*timeEpochString, (size_t)length, format, tm);
}


/**
 * Releasing the static variable to rebuild static variable for unit test
 * 
 * @param instance [Time*] The pointer to the time instance
 */
static void releaseInitializedFileParserInitialization(Time* instance) {
    *(instance->timeEpochPointer) = 0;
}