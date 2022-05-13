
#ifndef Musig2Sr25519Header_h
#define Musig2Sr25519Header_h

#include <stdio.h>
#include <stdint.h>

#endif /* Musig2Sr25519Header_h */

const char *get_my_privkey(const char *phrase);

const char *get_my_pubkey(const char *privkey);

typedef struct State State;

State *get_round1_state();

char *encode_round1_state(State *state);

State *decode_round1_state(const char *round1_state);

char *get_round1_msg(State *state);

char *get_round2_msg(State *state, uint32_t message, const char *privkey, const char *pubkeys, const char *received_round1_msg);

char *get_signature(const char *round2_msg);

char *get_key_agg(const char *pubkeys);

char *generate_threshold_pubkey(const char *pubkeys, uint8_t threshold);

char *generate_control_block(const char *pubkeys, uint8_t threshold, const char *agg_pubkey);