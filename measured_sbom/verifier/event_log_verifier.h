#ifndef EVENT_LOG_VERIFIER_H
#define EVENT_LOG_VERIFIER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <tss2/tss2_tpm2_types.h>

#define HASH_SIZE 32          // SHA-256 hash size in bytes
#define MAX_RIM_FILES 10      // Maximum number of RIM files supported

// Structure to store RIM file data (reference digests)
typedef struct {
    char name[100];           // Name of the file in the RIM entry
    uint8_t digest[HASH_SIZE];// SHA-256 digest for verification
} RIM_File;

// Structure for holding multiple RIM file entries
typedef struct {
    RIM_File files[MAX_RIM_FILES]; // Array of RIM files
    size_t file_count;             // Count of valid RIM files
} RIM_Payload;

// Main API functions
void initialize_rim_payload(RIM_Payload *rim_payload);
bool parse_event_log_from_file(const char *filename, const RIM_Payload *rim_payload);

#endif // EVENT_LOG_VERIFIER_H