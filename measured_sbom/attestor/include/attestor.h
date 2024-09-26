#ifndef ATTESTOR_H
#define ATTESTOR_H

#include <stdint.h>
#include <stddef.h>

// Function to process the attestation request from the verifier
// Parameters: 
// - request_buffer: Pointer to the buffer containing the serialized attestation request
// - request_size: Size of the request buffer
void process_attestation_request(uint8_t *request_buffer, size_t request_size);

// Function to send the attestation response back to the verifier
// This function will serialize PCR values, measurement logs, and other details
void send_attestation_response();

// Function to collect PCR values and measurement logs for the response
// The collected data will be used in send_attestation_response
void collect_attestation_data();

#endif // ATTESTOR_H