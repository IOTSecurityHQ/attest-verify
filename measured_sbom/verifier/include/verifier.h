#ifndef VERIFIER_H
#define VERIFIER_H

#include <stdint.h>
#include <stddef.h>

// Function to send an attestation request to the attestor
// The request will include a nonce to ensure freshness of the attestation
void send_attestation_request();

// Function to process the attestation response from the attestor
// Parameters:
// - response_buffer: Pointer to the buffer containing the serialized attestation response
// - response_size: Size of the response buffer
void process_attestation_response(uint8_t *response_buffer, size_t response_size);

// Function to verify the received PCR values and measurement logs
// This function will compare the received logs with expected values
// Returns: 1 if verification succeeds, 0 otherwise
int verify_attestation_data();

#endif // VERIFIER_H