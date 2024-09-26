#include <stdio.h>
#include <stdlib.h>
#include "attestation.pb-c.h"  // Protobuf definitions for attestation
#include "verifier.h"

void send_attestation_request() {
    AttestationRequest request = ATTESTATION_REQUEST__INIT;  // Init request struct
    request.verifier_id = "verifier123";
    
    // Random nonce (example)
    uint8_t nonce[16] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                         0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10};
    request.nonce.data = nonce;
    request.nonce.len = 16;

    // Serialize the request
    size_t request_size = attestation_request__get_packed_size(&request);
    uint8_t *request_buffer = malloc(request_size);
    attestation_request__pack(&request, request_buffer);

    printf("Serialized AttestationRequest (size: %zu):\n", request_size);
    for (size_t i = 0; i < request_size; i++) {
        printf("%02x ", request_buffer[i]);
    }
    printf("\n");

    // Simulate sending request (in real use case, send over network)

    // Free the allocated memory
    free(request_buffer);
}

// Function to process attestation response from the attestor
void process_attestation_response(uint8_t *response_buffer, size_t response_size) {
    AttestationResponse *response = attestation_response__unpack(NULL, response_size, response_buffer);
    if (!response) {
        fprintf(stderr, "Error unpacking AttestationResponse\n");
        return;
    }

    // Verify the nonce and PCR values here (simplified for example)
    printf("Received attestor ID: %s\n", response->attestor_id);
    
    for (size_t i = 0; i < response->n_pcrs; i++) {
        printf("PCR %d value: ", response->pcrs[i]->index);
        for (size_t j = 0; j < response->pcrs[i]->value.len; j++) {
            printf("%02x", response->pcrs[i]->value.data[j]);
        }
        printf("\n");
    }

    // Iterate over event logs
    for (size_t i = 0; i < response->event_log->n_events; i++) {
        TCGEvent *event = response->event_log->events[i];
        printf("Event %d (PCR %d): %s\n", event->recnum, event->pcr_index, event->event_content);
    }

    // Free memory
    attestation_response__free_unpacked(response, NULL);
}