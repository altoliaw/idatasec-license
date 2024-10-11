#include "../Headers/Test_Time.h"

/**
 * Main process for the model unit test
 */
int main() {
    int isFault = 0;
    isFault |= cmocka_run_group_tests(Test_Time_Group, NULL, NULL);
    return isFault;
}

/**
 * getEpochProcess test
 */
void Test_Time_getEpochProcess(void** State) {
    Time instance;
    Time_Constrcut(&instance);
    time_t now = time(NULL);
    long resultTime = instance.getEpoch(&instance, 0);

    // Verifying the two times one comes from the function and the other
    // comes from the class method
    assert_int_equal((long)now, resultTime);
    // Releasing the static variable
    instance.releaseInitializedFileParserInitialization(&instance);
    Time_Destrcut(&instance);
}

/**
 * getStringToEpoch test
 */
void Test_Time_getStringToEpoch(void** State) {
    Time instance;
    Time_Constrcut(&instance);
    long utc = 1760025600;

    long resultTime = instance.getStringToEpoch(&instance, "2025-10-10 00:00:00");
    // Verifying the two times one comes from the function and the other
    // comes from the class method
    assert_int_equal(utc, resultTime);

    // Releasing the static variable
    instance.releaseInitializedFileParserInitialization(&instance);
    Time_Destrcut(&instance);
}

/**
 * getEpochToString test
 */
void Test_Time_getEpochToString(void** State) {
    Time instance;
    Time_Constrcut(&instance);
    long utc = 1760025600;
	const unsigned char* timeString = "2025-10-10 00:00:00";
	const unsigned char* timeUTCString = "2025-10-09 16:00:00";
    long resultTime = instance.getStringToEpoch(&instance, (const char*)timeString);
    // Verifying the two times one comes from the function and the other
    // comes from the class method
    assert_int_equal(utc, resultTime);

    unsigned char* timeEpochString = NULL;
    instance.getEpochToString(&instance, "%Y-%m-%d %H:%M:%S", UTC, resultTime, &timeEpochString);
	assert_string_equal(timeEpochString, timeUTCString);

	// Verifying the two times one comes from the function and the other
    // comes from the class method
    assert_int_equal(utc, resultTime);

    if (timeEpochString != NULL) {
        free(timeEpochString);
        timeEpochString = NULL;
    }

    // Releasing the static variable
    instance.releaseInitializedFileParserInitialization(&instance);
    Time_Destrcut(&instance);
}