// attestor.h
#ifndef ATTESTOR_H
#define ATTESTOR_H

#include <stdint.h>
#include <stddef.h>

// Constants
#define TPM_PCR_COUNT 24  /**< TPM 2.0 typically has 24 PCR registers */

// Enumerations

/**
 * @enum AttestationState
 * @brief Enumeration of states in the attestation protocol state machine.
 */
typedef enum {
    STATE_INIT,             /**< Initial state */
    STATE_PROCESS_REQUEST,  /**< Processing the attestation request */
    STATE_COLLECT_DATA,     /**< Collecting PCR values and measurement logs */
    STATE_SEND_RESPONSE,    /**< Sending the attestation response */
    STATE_DONE,             /**< Attestation protocol completed */
    STATE_ERROR             /**< An error occurred */
} AttestationState;

// Structures

/**
 * @struct PCR_Data
 * @brief Structure to hold a PCR value and its size.
 */
typedef struct {
    uint8_t *value;  /**< Pointer to the PCR value data */
    size_t size;     /**< Size of the PCR value data */
} PCR_Data;

/**
 * @struct AttestationContext
 * @brief Context structure for the attestation protocol state machine.
 */
typedef struct {
    AttestationState state;       /**< Current state of the attestation protocol */
    uint8_t *request_buffer;      /**< Buffer containing the attestation request */
    size_t request_size;          /**< Size of the request buffer */
    PCR_Data *pcr_data_array;     /**< Array of PCR_Data structures */
    size_t num_pcrs;              /**< Number of PCRs collected */
    uint8_t *measurement_log;     /**< Buffer containing the measurement logs */
    size_t log_size;              /**< Size of the measurement log buffer */
} AttestationContext;

// Function Prototypes

/**
 * @brief Collects all PCR values from the TPM.
 *
 * This function reads all Platform Configuration Register (PCR) values from the TPM and stores them in an array of
 * PCR_Data structures. Each PCR_Data structure contains a pointer to the PCR value data and its size.
 *
 * @param[out] pcr_data_array  Pointer to the array where PCR_Data structures will be stored.
 * @param[out] num_pcrs        Pointer to a size_t variable where the number of PCRs collected will be stored.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int collect_all_pcr_values(PCR_Data **pcr_data_array, size_t *num_pcrs);

/**
 * @brief Collects measurement logs from the platform.
 *
 * This function retrieves the measurement logs from the platform, which may include logs from the boot process and
 * other measurements that are critical for attestation.
 *
 * @param[out] measurement_log Pointer to the buffer where the measurement log will be stored.
 * @param[out] log_size        Pointer to a size_t variable where the size of the measurement log will be stored.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int collect_measurement_logs(uint8_t **measurement_log, size_t *log_size);

/**
 * @brief Processes the attestation request received from the verifier.
 *
 * This function deserializes the attestation request using Protocol Buffers and extracts necessary information,
 * such as the nonce provided by the verifier.
 *
 * @param[in] request_buffer   Pointer to the buffer containing the serialized attestation request.
 * @param[in] request_size     Size of the request buffer.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int process_attestation_request(uint8_t *request_buffer, size_t request_size);

/**
 * @brief Sends the attestation response back to the verifier.
 *
 * This function serializes the attestation response, including the collected PCR values and measurement logs,
 * and sends it back to the verifier. The response is constructed using Protocol Buffers.
 *
 * @param[in] pcr_data_array   Array of PCR_Data structures containing the PCR values.
 * @param[in] num_pcrs         Number of PCRs in the pcr_data_array.
 * @param[in] measurement_log  Buffer containing the measurement logs.
 * @param[in] log_size         Size of the measurement log buffer.
 *
 * @return Returns 0 on success, or -1 on failure.
 */
int send_attestation_response(PCR_Data *pcr_data_array, size_t num_pcrs,
                              uint8_t *measurement_log, size_t log_size);

/**
 * @brief Runs the attestation protocol using a state machine.
 *
 * This function manages the attestation protocol by transitioning through different states,
 * from initializing the context to processing the request, collecting data, sending the response,
 * and handling errors. It uses the AttestationContext structure to maintain state.
 *
 * @param[in,out] ctx  Pointer to the AttestationContext structure.
 */
void run_attestation_protocol(AttestationContext *ctx);

#endif // ATTESTOR_H