package musig2sr25519

/*
#cgo LDFLAGS: -L../lib -lmusig2_sr25519_dll
#include <stdlib.h>
#include "../lib/Musig2Sr25519Header.h"
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"strings"
	"unsafe"
)

func verifyResult(result *C.char) (string, error) {
	output := C.GoString(result)
	_, err := hex.DecodeString(output)
	if err != nil {
		return "", errors.New(output)
	} else {
		return output, nil
	}
}

// Generating private keys from mnemonics
func GetMyPrivkey(phrase string) (string, error) {
	cPhrase := C.CString(phrase)
	defer C.free(unsafe.Pointer(cPhrase))
	result := C.get_my_privkey(cPhrase)
	return verifyResult(result)
}

// Generating a public key from a private key
func GetMyPubkey(priv string) (string, error) {
	cPriv := C.CString(priv)
	defer C.free(unsafe.Pointer(cPriv))
	result := C.get_my_pubkey(cPriv)
	return verifyResult(result)
}

// Aggregate multiple public keys into one public
// key with a 32-byte public key.
//
// full pubkey: 65 bytes, take 1-33 bytes
// compressed pubkey: 33 bytes, take 1-33 bytes
func GetAggPublicKey(pubkeys []string) (string, error) {
	allPubkeys := strings.Join(pubkeys, "")
	cPubkeys := C.CString(allPubkeys)
	defer C.free(unsafe.Pointer(cPubkeys))
	result := C.get_key_agg(cPubkeys)
	return verifyResult(result)
}

// Get round1 state
func GetRound1State() *C.State {
	return C.get_round1_state()
}

// Persistent first round state
func EncodeRound1State(state *C.State) string {
	encoded := C.encode_round1_state(state)
	return C.GoString(encoded)
}

// Parsing the first round of states
// from the stored string
func DecodeRound1State(state string) *C.State {
	cState := C.CString(state)
	defer C.free(unsafe.Pointer(cState))
	return C.decode_round1_state(cState)
}

// Get the message to be broadcast in
// the first round of communication
func GetRound1Msg(state *C.State) (string, error) {
	result := C.get_round1_msg(state)
	return verifyResult(result)
}

// Get the message to be broadcast in
// the second round of communication
func GetRound2Msg(state *C.State, msg uint32, priv string, pubkeys []string, receivedRound1Msg []string) (string, error) {
	cPriv := C.CString(priv)
	defer C.free(unsafe.Pointer(cPriv))
	cPubkeys := C.CString(strings.Join(pubkeys, ""))
	defer C.free(unsafe.Pointer(cPubkeys))
	cReceivedRound1Msg := C.CString(strings.Join(receivedRound1Msg, ""))
	defer C.free(unsafe.Pointer(cReceivedRound1Msg))
	result := C.get_round2_msg(state, C.uint32_t(msg), cPriv, cPubkeys, cReceivedRound1Msg)
	return verifyResult(result)
}

// Generate aggregated signatures with
// all received second round messages
func GetAggSignature(reveivedRound2Msg []string) (string, error) {
	cReceivedRound2Msg := C.CString(strings.Join(reveivedRound2Msg, ""))
	defer C.free(unsafe.Pointer(cReceivedRound2Msg))
	result := C.get_signature(cReceivedRound2Msg)
	return verifyResult(result)
}

// Generate thresheld public key
func GenerateThresholdPubkey(pubkeys []string, threshold uint8) (string, error) {
	cPubkeys := C.CString(strings.Join(pubkeys, ""))
	defer C.free(unsafe.Pointer(cPubkeys))
	result := C.generate_threshold_pubkey(cPubkeys, C.uint8_t(threshold))
	return verifyResult(result)
}

// Generate a proof of the aggregated public key by
// passing in the public key and signature threshold of
// all signers and the aggregated public key of everyone
// who performed the signature this time.
func GenerateControlBlock(pubkeys []string, threshold uint8, sigAggPubkey string) (string, error) {
	cPubkeys := C.CString(strings.Join(pubkeys, ""))
	defer C.free(unsafe.Pointer(cPubkeys))
	cSigAggPubkey := C.CString(sigAggPubkey)
	defer C.free(unsafe.Pointer(cSigAggPubkey))
	result := C.generate_control_block(cPubkeys, C.uint8_t(threshold), cSigAggPubkey)
	return verifyResult(result)
}
