// Implement a simple state machine to run attestor side of the attestation protocol. This code reads the one or more 
// PCR value from TPM and measurement logs from the platform. The attestation data is sent to the verifier. 

#include <stdio.h>
#include <stdlib.h>
#include "attestation.pb-c.h"  // Protobuf definitions for attestation
#include "attestor.h"



// Structure to hold PCR value and its size
typedef struct {
    uint8_t *value;
    size_t size;
} PCR_Data;

// Read all PCR values from TPM
int collect_all_pcr_values(PCR_Data **pcr_data_array, size_t *num_pcrs) {
    // For demonstration purposes, we'll use dummy data
    // In a real use case, this function would collect data from the TPM

    *num_pcrs = 24; // TPM 2.0 typically has 24 PCR registers

    // Allocate memory for the array of PCR_Data structures
    *pcr_data_array = malloc(*num_pcrs * sizeof(PCR_Data));
    if (*pcr_data_array == NULL) {
        fprintf(stderr, "Error allocating memory for PCR data array\n");
        return -1;
    }

    for (size_t i = 0; i < *num_pcrs; i++) {
        // Dummy PCR value for each PCR
        const char *dummy_pcr = "dummy_pcr_value";
        size_t pcr_size = strlen(dummy_pcr);

        // Allocate memory for each PCR value
        (*pcr_data_array)[i].value = malloc(pcr_size);
        if ((*pcr_data_array)[i].value == NULL) {
            fprintf(stderr, "Error allocating memory for PCR value %zu\n", i);

            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
                free((*pcr_data_array)[j].value);
            }
            free(*pcr_data_array);
            return -1;
        }

        // Copy the dummy PCR value
        memcpy((*pcr_data_array)[i].value, dummy_pcr, pcr_size);
        (*pcr_data_array)[i].size = pcr_size;
    }

    return 0;  // Success
}

// Read measurement logs from the platform
int collect_measurement_logs(uint8_t **measurement_log, size_t *log_size) {
    // For demonstration purposes, we'll use dummy data
    // In a real use case, this function would collect data from the system

    // Dummy measurement log
    const char *dummy_log = "dummy_measurement_log";
    *log_size = strlen(dummy_log);

    *measurement_log = malloc(*log_size);
    if (*measurement_log == NULL) {
        fprintf(stderr, "Error allocating memory for measurement log\n");
        return -1;
    }
    memcpy(*measurement_log, dummy_log, *log_size);

    return 0;  // Success
}
void process_attestation_request(uint8_t *request_buffer, size_t request_size) {
    AttestationRequest *request = attestation_request__unpack(NULL, request_size, request_buffer);
    if (!request) {
        fprintf(stderr, "Error unpacking AttestationRequest\n");
        return;
    }

    // Print received nonce (for demo purposes)
    printf("Received nonce: ");
    for (size_t i = 0; i < request->nonce.len; i++) {
        printf("%02x", request->nonce.data[i]);
    }
    printf("\n");

    // Free memory
    attestation_request__free_unpacked(request, NULL);
}

void send_attestation_response() {
    AttestationResponse response = ATTESTATION_RESPONSE__INIT;  // Init response struct
    response.attestor_id = "attestor456";

    
    // Serialize the response
    size_t response_size = attestation_response__get_packed_size(&response);
    uint8_t *response_buffer = malloc(response_size);
    attestation_response__pack(&response, response_buffer);

    printf("Serialized AttestationResponse (size: %zu):\n", response_size);
    for (size_t i = 0; i < response_size; i++) {
        printf("%02x ", response_buffer[i]);
    }
    printf("\n");

    // Simulate sending response (in real use case, send over network)

    // Free the allocated memory
    free(response_buffer);
}


typedef enum {
    STATE_INIT,
    STATE_PROCESS_REQUEST,
    STATE_COLLECT_DATA,
    STATE_SEND_RESPONSE,
    STATE_DONE,
    STATE_ERROR
} AttestationState;

typedef struct {
    AttestationState state;
    uint8_t *request_buffer;
    size_t request_size;
    uint8_t *pcr_value;
    size_t pcr_size;
    uint8_t *measurement_log;
    size_t log_size;
} AttestationContext;

void run_attestation_protocol(AttestationContext *ctx) {
    while (ctx->state != STATE_DONE && ctx->state != STATE_ERROR) {
        switch (ctx->state) {
            case STATE_INIT:
                // Initialize context
                ctx->pcr_value = NULL;
                ctx->measurement_log = NULL;
                ctx->state = STATE_PROCESS_REQUEST;
                break;

            case STATE_PROCESS_REQUEST:
                process_attestation_request(ctx->request_buffer, ctx->request_size);
                ctx->state = STATE_COLLECT_DATA;
                break;

            case STATE_COLLECT_DATA:
                if (collect_attestation_data(&ctx->pcr_value, &ctx->pcr_size, &ctx->measurement_log, &ctx->log_size) == 0) {
                    ctx->state = STATE_SEND_RESPONSE;
                } else {
                    ctx->state = STATE_ERROR;
                }
                break;

            case STATE_SEND_RESPONSE:
                send_attestation_response();
                ctx->state = STATE_DONE;
                break;

            case STATE_ERROR:
                fprintf(stderr, "An error occurred during the attestation protocol\n");
                ctx->state = STATE_DONE;
                break;

            default:
                fprintf(stderr, "Unknown state\n");
                ctx->state = STATE_ERROR;
                break;
        }
    }

    // Clean up
    if (ctx->pcr_value) {
        free(ctx->pcr_value);
    }
    if (ctx->measurement_log) {
        free(ctx->measurement_log);
    }
}

