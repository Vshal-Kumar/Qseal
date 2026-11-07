/*
 * qseal/src/error.c
 *
 * Error string conversion for QSEAL.
 */

#include "qseal/error.h"

const char *qseal_strerror(qseal_error_t err) {
    switch (err) {
        case QSEAL_SUCCESS:               return "Success";
        case QSEAL_ERR_INVALID_ARG:       return "Invalid argument";
        case QSEAL_ERR_NOMEM:             return "Out of memory";
        case QSEAL_ERR_IO:                return "Input/output error";
        case QSEAL_ERR_PERMISSION:        return "Permission denied";
        
        case QSEAL_ERR_CONFIG_NOT_FOUND:  return "Configuration file not found";
        case QSEAL_ERR_CONFIG_PARSE:      return "Configuration parse error";
        case QSEAL_ERR_CONFIG_VALIDATE:   return "Configuration validation failed";
        case QSEAL_ERR_CONFIG_WRITE:      return "Failed to write configuration file";
        
        case QSEAL_ERR_DEVICE_PROBE:      return "Device hardware profiling failed";
        case QSEAL_ERR_INSUFFICIENT_MEM:  return "Insufficient system memory for operation";
        
        case QSEAL_ERR_PROFILE_NOT_FOUND: return "Cryptographic profile not found in registry";
        case QSEAL_ERR_PROFILE_UNAVAIL:   return "Cryptographic profile unavailable on this device";
        case QSEAL_ERR_POLICY_VIOLATION:  return "Action violates declared security policy";
        case QSEAL_ERR_NO_COMPAT_PROFILE: return "No mutually compatible profile found";
        case QSEAL_ERR_DOWNGRADE_BLOCKED: return "Cryptographic downgrade attempt blocked by policy";
        
        case QSEAL_ERR_IDENTITY_MISSING:  return "Device identity key material missing";
        case QSEAL_ERR_IDENTITY_CORRUPT:  return "Device identity key material corrupted or invalid";
        case QSEAL_ERR_IDENTITY_GEN:      return "Keypair generation failed";
        case QSEAL_ERR_TRUST_VERIFY:      return "Peer identity verification failed";
        case QSEAL_ERR_AUTH_REJECTED:     return "Peer authentication rejected by policy";
        
        case QSEAL_ERR_SOCKET_INIT:       return "Socket initialization failed";
        case QSEAL_ERR_SOCKET_BIND:       return "Failed to bind network socket";
        case QSEAL_ERR_CONNECT_TIMEOUT:   return "Connection timed out";
        case QSEAL_ERR_NETWORK_SEND:      return "Failed to transmit datagram";
        case QSEAL_ERR_NETWORK_RECV:      return "Failed to receive datagram";
        case QSEAL_ERR_DISCONNECT:        return "Peer disconnected";
        
        case QSEAL_ERR_HANDSHAKE_FAIL:    return "Cryptographic handshake failed";
        case QSEAL_ERR_AEAD_VERIFY:       return "AEAD authentication tag verification failed";
        case QSEAL_ERR_REPLAY_DETECTED:   return "Duplicate/stale datagram rejected by replay window";
        case QSEAL_ERR_MALFORMED_PACKET:  return "Malformed packet rejected by bounds check";
        case QSEAL_ERR_BACKEND_INIT:      return "Cryptographic backend initialization failed";
        
        case QSEAL_ERR_SERVICE_RUNNING:   return "Service is already running";
        case QSEAL_ERR_SERVICE_STOPPED:   return "Service is stopped";
        default:                               return "Unknown error";
    }
}
