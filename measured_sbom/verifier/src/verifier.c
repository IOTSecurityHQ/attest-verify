// verifier_protocol.c
// Implements the verifier side of the attestation protocol.
// This code sends an attestation request to the attestor, waits for the response,
// and processes the attestation response using a state machine.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attestation.pb-c.h"  // Protobuf definitions for attestation
#include "verifier.h"

// Enumerations

/**
 * @enum VerifierState
 * @brief Enumeration of states in the verifier's attestation protocol state machine.
 */
typedef enum {
    VERIFIER_STATE_INIT,            /**< Initial state */
    VERIFIER_STATE_SEND_REQUEST,    /**< Sending the attestation request */
    VERIFIER_STATE_WAIT_FOR_RESPONSE,/**< Waiting for the attestation response */
    VERIFIER_STATE_PROCESS_RESPONSE,/**< Processing the attestation response */
    VERIFIER_STATE_DONE,            /**< Attestation protocol completed */
    VERIFIER_STATE_ERROR            /**< An error occurred */
} VerifierState;

// Structures

/**
 * @struct VerifierContext
 * @brief Context structure for the verifier's attestation protocol state machine.
 */
typedef struct {
    VerifierState state;            /**< Current state of the verifier's protocol */
    uint8_t *request_buffer;        /**< Buffer containing the attestation request */
    size_t request_size;            /**< Size of the request buffer */
    uint8_t *response_buffer;       /**< Buffer containing the attestation response */
    size_t response_size;           /**< Size of the response buffer */
    int attestation_result;         /**< Result of the attestation (0 = pass, -1 = fail) */
} VerifierContext;

// Function Prototypes

int create_attestation_request(uint8_t **request_buffer, size_t *request_size);
int send_attestation_request(uint8_t *request_buffer, size_t request_size);
int receive_attestation_response(uint8_t **response_buffer, size_t *response_size);
int process_attestation_response(uint8_t *response_buffer, size_t response_size, int *attestation_result);

int verify_quote_signature(const uint8_t *quote, size_t quote_size);
int replay_measurement_log(const uint8_t *measurement_log, size_t log_size, uint8_t **replayed_pcrs, size_t *num_pcrs);
int compare_pcr_values(const uint8_t *pcr_values, size_t num_pcrs, const uint8_t *replayed_pcrs);
int check_measurement_log_against_rim(const uint8_t *measurement_log, size_t log_size);

void run_verifier_protocol(VerifierContext *ctx);

// Function Implementations

/**
 * @brief Creates an attestation request.
 *
 * This function constructs an attestation request message, including a nonce, and serializes it using Protocol Buffers.
 *
 * @param[out] request_buffer Pointer to the buffer where the serialized request will be stored.
 * @param[out] request_size   Pointer to a size_t variable where the size of the request will be stored.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int create_attestation_request(uint8_t **request_buffer, size_t *request_size) {
    AttestationRequest request = ATTESTATION_REQUEST__INIT;  // Initialize the request structure

    // Generate a nonce (for demonstration purposes, we'll use dummy data)
    const char *dummy_nonce = "dummy_nonce";
    request.nonce.data = (uint8_t *)dummy_nonce;
    request.nonce.len = strlen(dummy_nonce);

    // Serialize the request
    *request_size = attestation_request__get_packed_size(&request);
    *request_buffer = malloc(*request_size);
    if (*request_buffer == NULL) {
        fprintf(stderr, "Error allocating memory for request buffer\n");
        return -1;
    }
    attestation_request__pack(&request, *request_buffer);

    return 0;  // Success
}

/**
 * @brief Sends the attestation request to the attestor.
 *
 * This function simulates sending the attestation request over the network to the attestor.
 *
 * @param[in] request_buffer Pointer to the buffer containing the serialized request.
 * @param[in] request_size   Size of the request buffer.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int send_attestation_request(uint8_t *request_buffer, size_t request_size) {
    // TODO: Implement network sending code
    // For demonstration purposes, we'll assume the request is sent successfully
    printf("Attestation request sent (size: %zu bytes)\n", request_size);
    return 0;
}

/**
 * @brief Receives the attestation response from the attestor.
 *
 * This function simulates receiving the attestation response over the network.
 *
 * @param[out] response_buffer Pointer to the buffer where the response will be stored.
 * @param[out] response_size   Pointer to a size_t variable where the size of the response will be stored.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int receive_attestation_response(uint8_t **response_buffer, size_t *response_size) {
    // TODO: Implement network receiving code
    // For demonstration purposes, we'll use dummy data
    const char *dummy_response = "dummy_response_data";
    *response_size = strlen(dummy_response);
    *response_buffer = malloc(*response_size);
    if (*response_buffer == NULL) {
        fprintf(stderr, "Error allocating memory for response buffer\n");
        return -1;
    }
    memcpy(*response_buffer, dummy_response, *response_size);

    printf("Attestation response received (size: %zu bytes)\n", *response_size);
    return 0;
}

/**
 * @brief Processes the attestation response received from the attestor.
 *
 * This function deserializes the attestation response, verifies the signature, replays the measurement log,
 * compares PCR values, and checks the measurement log against the RIM.
 *
 * @param[in]  response_buffer     Pointer to the buffer containing the serialized response.
 * @param[in]  response_size       Size of the response buffer.
 * @param[out] attestation_result  Pointer to an integer where the attestation result will be stored (0 = pass, -1 = fail).
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int process_attestation_response(uint8_t *response_buffer, size_t response_size, int *attestation_result) {
    // Deserialize the response
    AttestationResponse *response = attestation_response__unpack(NULL, response_size, response_buffer);
    if (!response) {
        fprintf(stderr, "Error unpacking AttestationResponse\n");
        return -1;
    }

    // Placeholder: Verify the signature of the quote
    if (!verify_quote_signature(response->quote.data, response->quote.len)) {
        fprintf(stderr, "Quote signature verification failed\n");
        attestation_response__free_unpacked(response, NULL);
        *attestation_result = -1;
        return -1;
    }

    // Placeholder: Replay the measurement log
    uint8_t *replayed_pcrs = NULL;
    size_t num_replayed_pcrs = 0;
    if (!replay_measurement_log(response->measurement_log.data, response->measurement_log.len, &replayed_pcrs, &num_replayed_pcrs)) {
        fprintf(stderr, "Measurement log replay failed\n");
        attestation_response__free_unpacked(response, NULL);
        *attestation_result = -1;
        return -1;
    }

    // Placeholder: Compare replayed PCRs with received PCR values
    if (!compare_pcr_values(response->pcr_values.data, response->pcr_values.len, replayed_pcrs)) {
        fprintf(stderr, "PCR value comparison failed\n");
        free(replayed_pcrs);
        attestation_response__free_unpacked(response, NULL);
        *attestation_result = -1;
        return -1;
    }

    // Placeholder: Check measurement log against RIM
    if (!check_measurement_log_against_rim(response->measurement_log.data, response->measurement_log.len)) {
        fprintf(stderr, "Measurement log validation against RIM failed\n");
        free(replayed_pcrs);
        attestation_response__free_unpacked(response, NULL);
        *attestation_result = -1;
        return -1;
    }

    // If all checks pass
    printf("Attestation successful\n");
    *attestation_result = 0;

    // Clean up
    free(replayed_pcrs);
    attestation_response__free_unpacked(response, NULL);

    return 0;  // Success
}

/**
 * @brief Placeholder function to verify the signature of the quote.
 *
 * @param[in] quote       Pointer to the quote data.
 * @param[in] quote_size  Size of the quote data.
 *
 * @return Returns non-zero (e.g., 1) on success, or 0 on failure.
 */
int verify_quote_signature(const uint8_t *quote, size_t quote_size) {
    // TODO: Implement signature verification
    // For demonstration purposes, we'll assume the signature is valid
    return 1;  // Success
}

/**
 * @brief Placeholder function to replay the measurement log.
 *
 * @param[in]  measurement_log     Pointer to the measurement log data.
 * @param[in]  log_size            Size of the measurement log data.
 * @param[out] replayed_pcrs       Pointer to the buffer where replayed PCRs will be stored.
 * @param[out] num_pcrs            Pointer to a size_t variable where the number of replayed PCRs will be stored.
 *
 * @return Returns non-zero (e.g., 1) on success, or 0 on failure.
 */
int replay_measurement_log(const uint8_t *measurement_log, size_t log_size, uint8_t **replayed_pcrs, size_t *num_pcrs) {
    // TODO: Implement measurement log replay
    // For demonstration purposes, we'll create dummy data
    *num_pcrs = TPM_PCR_COUNT;
    size_t pcr_data_size = *num_pcrs * sizeof(uint8_t);  // Assuming 1 byte per PCR for simplicity
    *replayed_pcrs = malloc(pcr_data_size);
    if (*replayed_pcrs == NULL) {
        fprintf(stderr, "Error allocating​⬤