#include "event_log_verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_ERR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) fprintf(stdout, "[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)

/**
 * Initializes the RIM payload with test data.
 * This function should be modified to initialize real RIM data in production.
 */
void initialize_rim_payload(RIM_Payload *rim_payload) {
    if (!rim_payload) {
        LOG_ERR("RIM payload initialization failed: NULL pointer");
        return;
    }

    rim_payload->file_count = 2;

    // Initialize RIM entry for iotBase
    strncpy(rim_payload->files[0].name, "Example.com.iotBase.bin", sizeof(rim_payload->files[0].name) - 1);
    const uint8_t hash1[HASH_SIZE] = { /* SHA-256 hash for file 1 */ };
    memcpy(rim_payload->files[0].digest, hash1, HASH_SIZE);

    // Initialize RIM entry for iotExec
    strncpy(rim_payload->files[1].name, "iotExec.bin", sizeof(rim_payload->files[1].name) - 1);
    const uint8_t hash2[HASH_SIZE] = { /* SHA-256 hash for file 2 */ };
    memcpy(rim_payload->files[1].digest, hash2, HASH_SIZE);
}

/**
 * Finds a matching RIM file entry by name.
 * Returns a pointer to the RIM_File if found, otherwise NULL.
 */
static const RIM_File* find_rim_file(const RIM_Payload *rim_payload, const char *event_name) {
    if (!rim_payload || !event_name) {
        LOG_ERR("RIM file lookup failed: NULL parameter");
        return NULL;
    }

    for (size_t i = 0; i < rim_payload->file_count; i++) {
        if (strcmp(rim_payload->files[i].name, event_name) == 0) {
            return &rim_payload->files[i];
        }
    }
    return NULL;
}

/**
 * Interprets a single event and verifies its digest against the RIM entry.
 * Logs verification success or failure for each event.
 */
static bool interpret_event(const TCG_EVENT *event, const RIM_Payload *rim_payload, size_t event_num) {
    if (!event || !rim_payload) {
        LOG_ERR("Event interpretation failed: NULL parameter");
        return false;
    }

    const char *event_name = (const char*)event->Event;
    const RIM_File *rim_entry = find_rim_file(rim_payload, event_name);

    if (!rim_entry) {
        LOG_WARN("Event %zu: No matching RIM entry for '%s'", event_num, event_name);
        return false;
    }

    bool digest_match = (memcmp(event->digest, rim_entry->digest, HASH_SIZE) == 0);
    if (digest_match) {
        LOG_INFO("Event %zu: Digest verification succeeded for '%s'", event_num, event_name);
    } else {
        LOG_ERR("Event %zu: Digest mismatch for '%s'", event_num, event_name);
    }

    return digest_match;
}

/**
 * Cast an event type on to event log and keep shifting to find more events. 
 * TODO: Need to study possbility extra bytes and how this logic is resiliant to it.
 * Returns true if all events are successfully verified, false otherwise.
 */
static bool process_event_log(const BYTE *event_log, size_t log_size, const RIM_Payload *rim_payload) {
    if (!event_log || log_size == 0 || !rim_payload) {
        LOG_ERR("Event log processing failed: Invalid input");
        return false;
    }

    size_t offset = 0;
    size_t event_num = 1;
    bool all_verified = true;

    while (offset < log_size) {
        // Ensure there's enough space for an event structure
        if (log_size - offset < sizeof(TCG_EVENT)) {
            LOG_ERR("Incomplete event header at offset %zu", offset);
            all_verified = false;
            break;
        }

        const TCG_EVENT *event = (const TCG_EVENT *)(event_log + offset);
        // Event size is not known from type of event. there is a field that needs to be
        // raed to determine that. 
        size_t event_size = sizeof(TCG_EVENT) + event->eventDataSize;

        // Validate event size
        if (log_size - offset < event_size) {
            LOG_ERR("Incomplete event data at offset %zu", offset);
            all_verified = false;
            break;
        }

        // At this point we have isolated an event and will be send to this function 
        // for verification against the RIM. 
        if (!interpret_event(event, rim_payload, event_num)) {
            all_verified = false;
        }

        // Advance to the next event
        offset += event_size;
        event_num++;
    }

    return all_verified;
}

/**
 * Loads an event log from a binary file, processes each event, and verifies digests.
 * Returns true if all events pass verification, false otherwise.
 * This is expecting event log in PC STD format, not Canoncial Event Log (CEL).
 */
bool parse_event_log_from_file(const char *filename, const RIM_Payload *rim_payload) {
    if (!filename || !rim_payload) {
        LOG_ERR("Event log parsing failed: Invalid input");
        return false;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        LOG_ERR("Error opening file: %s", filename);
        return false;
    }

    // Determine file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    // Allocate memory for the event log
    BYTE *event_log = (BYTE*)malloc(file_size);
    if (!event_log) {
        LOG_ERR("Memory allocation failed for event log buffer");
        fclose(file);
        return false;
    }

    // Read the file into memory
    if (fread(event_log, 1, file_size, file) != file_size) {
        LOG_ERR("Error reading event log from file");
        free(event_log);
        fclose(file);
        return false;
    }
    fclose(file);

    // Process and verify each event in the log
    bool result = process_event_log(event_log, file_size, rim_payload);
    LOG_INFO("Event log verification %s", result ? "succeeded" : "failed");

    free(event_log);
    return result;
}