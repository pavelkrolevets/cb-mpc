#pragma once

#include <stdint.h>
#include <vector>

#include <cbmpc/crypto/base.h>
#include <cbmpc/protocol/ec_dkg.h>
#include <cbmpc/protocol/mpc_job.h>

namespace coinbase::mpc::ecdsampc {

/** Opaque context for step-wise ECDSA-MPC sign. Implementation in ecdsa_mp_steps.cpp. */
struct sign_ctx_t;

/** Allocate a sign context. Call sign_validate_and_begin then sign_step_1..10, then sign_ctx_destroy. */
sign_ctx_t* sign_ctx_create(void);
/** Free a sign context from sign_ctx_create. */
void sign_ctx_destroy(sign_ctx_t* ctx);

// 256 provides 64-bit statistical security due to OT Multiplication
constexpr int kappa = 256;

enum {
  ot_no_role = -1,
  ot_sender = 0,
  ot_receiver = 1,
};

typedef eckey::key_share_mp_t key_t;

// --- Step-wise sign API (same protocol as sign() above, split into rounds) ---

/** Validates inputs and initializes ctx for step-wise sign. Call once before sign_step_1. */
error_t sign_validate_and_begin(job_mp_t& job, key_t& key, mem_t msg, party_idx_t sig_receiver,
                                const std::vector<std::vector<int>>& ot_role_map, sign_ctx_t& ctx);

/** Step 1: 1st round pre-message — sid_i, c, h_consistency, s_i, Ei_gen, broadcast. */
error_t sign_step_1(job_mp_t& job, sign_ctx_t& ctx);
/** Step 2: 2nd round pre-message + first round signing — verify h_consistency, sid, h_gen, rho, pi_s, OT step1,
 * broadcast. */
error_t sign_step_2(job_mp_t& job, sign_ctx_t& ctx);
/** Step 3: 2nd round signing — verify commitments, E, R_bits, OT step2, broadcast. */
error_t sign_step_3(job_mp_t& job, sign_ctx_t& ctx);
/** Step 4: 3rd round — k_i, rho_i, eK_i, eRHO_i, pi, delta, OT step3, broadcast. */
error_t sign_step_4(job_mp_t& job, sign_ctx_t& ctx);
/** Step 5: 4th round — OT output_R, verify pi_eK/pi_eRHO, view, seed, v_theta, s[receiver], broadcast. */
error_t sign_step_5(job_mp_t& job, sign_ctx_t& ctx);
/** Step 6: 5th round — s[sender], rho_k_i, rho_x_i, eRHO_K, eRHO_X, F_*, pi_*, broadcast. */
error_t sign_step_6(job_mp_t& job, sign_ctx_t& ctx);
/** Step 7: 6th round — view.update, h, verify, Y, Z_*, pi_Z, broadcast. */
error_t sign_step_7(job_mp_t& job, sign_ctx_t& ctx);
/** Step 8: 7th round — verify h, pi_Z, h2, Z, W_*, pi_W, K_i, pi_K, broadcast. */
error_t sign_step_8(job_mp_t& job, sign_ctx_t& ctx);
/** Step 9: 8th round — verify h2, pi_W, pi_K, K, r, W check, m, beta, eB, pi_R_*, rho_k, send_message_all_to_one. */
error_t sign_step_9(job_mp_t& job, sign_ctx_t& ctx);
/** Step 10: Output — sig_receiver verifies and writes sig. */
error_t sign_step_10(job_mp_t& job, sign_ctx_t& ctx, buf_t& sig);

/** Deterministic hash of step output (for testing). step 1..9 use ctx; step 10 use sig. */
error_t sign_step_result_hash(const sign_ctx_t& ctx, int step, buf256_t& out);
void sign_step_10_result_hash(mem_t sig, buf256_t& out);

static party_set_t ot_senders_for(int i, int peers_count, std::vector<std::vector<int>> ot_role_map) {
  party_set_t s;
  for (int j = 0; j < peers_count; j++) {
    if (ot_role_map[i][j] == ot_receiver) s.add(j);
  }
  return s;
}

static party_set_t ot_receivers_for(int i, int peers_count, std::vector<std::vector<int>> ot_role_map) {
  party_set_t s;
  for (int j = 0; j < peers_count; j++) {
    if (ot_role_map[i][j] == ot_sender) s.add(j);
  }
  return s;
}

/**
 * This is a essentially a set intersection that returns [1, ..., n] - self - receivers
 */
static party_set_t get_senders_from_receivers(const job_mp_t& job, party_set_t receivers) {
  party_set_t senders = party_set_t(0);
  for (int i = 0; i < job.get_n_parties(); i++) {
    if (i == job.get_party_idx()) continue;
    if (receivers.has(i)) continue;
    senders.add(i);
  }
  return senders;
}

/**
 * Receivers get pairwise_msg and everyone sends and receives to_all_msgs which is like
 * a broadcast message communication
 */
template <typename OT_MSG, typename... TO_ALL_MSG>
error_t plain_broadcast_and_pairwise_message(job_mp_t& job, party_set_t receivers, OT_MSG& pairwise_msg,
                                             TO_ALL_MSG&... to_all_msgs) {
  error_t rv = UNINITIALIZED_ERROR;
  party_set_t senders = get_senders_from_receivers(job, receivers);

  if constexpr (sizeof...(to_all_msgs) == 0) {
    if (rv = job.group_message(receivers, senders, pairwise_msg)) return rv;
  } else {
    auto to_all_msg = job_mp_t::tie_msgs(to_all_msgs...);
    auto all_parties = party_set_t::all();

    if (rv = job.group_message(                          //
            std::tie(receivers, senders, pairwise_msg),  //
            std::tie(all_parties, all_parties, to_all_msg)))
      return rv;
  }

  return SUCCESS;
}

}  // namespace coinbase::mpc::ecdsampc