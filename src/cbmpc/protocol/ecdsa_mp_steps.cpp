#include "ecdsa_mp_steps.h"

#include <cbmpc/crypto/ro.h>
#include <cbmpc/protocol/ot.h>
#include <cbmpc/protocol/sid.h>
#include <cbmpc/zk/zk_elgamal_com.h>
#include <cbmpc/zk/zk_pedersen.h>

#include "util.h"

using namespace coinbase::mpc;

namespace coinbase::mpc::ecdsampc {

// These macros help with the readability of the code to make it easier to match the spec and the code
#define _ij msgs[j]
#define _i msg
#define _j received(j)
#define _js all_received()

// Common parameters used across steps. Set once in sign_validate_and_begin.
struct sign_ctx_common_t {
  job_mp_t* job = nullptr;
  key_t* key = nullptr;
  mem_t msg{};
  party_idx_t sig_receiver = 0;
  const std::vector<std::vector<int>>* ot_role_map = nullptr;
  int n = 0;
  int i = 0;
  int theta = 0;
  int peers_count = 0;
  int peer_index = 0;
  ecurve_t curve{};
};

// Step 1: sid_i, c, h_consistency, s_i, Ei_gen, broadcast.
struct sign_step_1_ctx_t {
  std::unique_ptr<job_mp_t::uniform_msg_t<buf_t>> sid_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf_t>> c;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h_consistency;
  bn_t s_i_val;
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> Ei_gen;
  buf256_t com_rand;
};

// Step 2: sid, h_gen, rho, pi_s, ot, R_bits_i, R, E_i, E (used through step 3).
struct sign_step_2_ctx_t {
  buf_t sid;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h_gen;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> rho;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_dl_t>> pi_s;
  std::vector<mpc::ot_protocol_pvw_ctx_t> ot;
  std::vector<coinbase::bits_t> R_bits_i;
  std::vector<std::vector<std::array<bool, 4>>> R;  // theta x n
  std::vector<ecc_point_t> E_i;
  ecc_point_t E;
};

// Step 4: k_i, rho_i, eK_i, eRHO_i, pi, delta.
struct sign_step_4_ctx_t {
  std::vector<std::array<bn_t, 4>> delta;  // flattened theta*n, index l*n+j
  bn_t k_i{}, rho_i{}, r_eK_i{}, r_eRHO_i{};
  bn_t x_i{};
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> eK_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> eRHO_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>> pi_eK;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>> pi_eRHO;
};

// Step 5: view, seed, v_theta, s_ot_sender, s_ot_receiver, X.
struct sign_step_5_ctx_t {
  std::vector<std::array<bn_t, 4>> X;  // flattened theta*n
  crypto::sha256_t view;
  std::unique_ptr<job_mp_t::nonuniform_msg_t<buf256_t>> seed;
  std::unique_ptr<job_mp_t::nonuniform_msg_t<std::array<bn_t, 4>>> v_theta;
  std::vector<std::array<bn_t, 4>> s_ot_sender;    // n
  std::vector<std::array<bn_t, 4>> s_ot_receiver;  // n
};

// Step 6: rho_k_i, rho_x_i, eRHO_K, eRHO_X, F_*, pi_*.
struct sign_step_6_ctx_t {
  bn_t rho_k_i{}, rho_x_i{};
  bn_t r_eRHO_K{}, r_eRHO_X{};
  bn_t r_F_eRHO_K{}, r_F_eRHO_X{};
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> eRHO_X;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> F_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> F_eRHO_X;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>> pi_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>> pi_eRHO_X;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_mult_t>> pi_F_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_mult_t>> pi_F_eRHO_X;
};

// Step 7: h, Y, Z_*, pi_Z.
struct sign_step_7_ctx_t {
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h;
  elg_com_t Y_eRHO_K{}, Y_eRHO_X{};
  bn_t r_Z_eRHO_K{}, r_Z_eRHO_X{}, o_Z_eRHO_K{}, o_Z_eRHO_X{};
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> Z_eRHO_K_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> Z_eRHO_X_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>> pi_Z_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>> pi_Z_eRHO_X;
};

// Step 8: h2, Z, W_*, pi_W, K_i, pi_K.
struct sign_step_8_ctx_t {
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h2;
  elg_com_t Z_eRHO_K{}, Z_eRHO_X{};
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> W_eRHO_K_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> W_eRHO_X_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::dh_t>> pi_W_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::dh_t>> pi_W_eRHO_X;
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> K_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>> pi_K;
};

// Step 9: K, r, m, beta, eB, pi_R_*, rho_k (used in step 10).
struct sign_step_9_ctx_t {
  ecc_point_t K{};
  bn_t r{};
  bn_t m{};
  std::unique_ptr<job_mp_t::uniform_msg_t<bn_t>> beta;
  std::vector<elg_com_t> eB;
  bn_t r_rho_x{}, rho_m{}, r_eR_RHO_X{}, r_eR_RHO_M{}, r_eB{};
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>> pi_R_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>> pi_R_eB;
  std::unique_ptr<job_mp_t::uniform_msg_t<bn_t>> rho_k;
  bn_t r_eRHO_K_val{};
};

// Aggregate context for step-wise sign. Opaque in ecdsa_mp_steps.h.
struct sign_ctx_t {
  sign_ctx_common_t common;
  sign_step_1_ctx_t step1;
  sign_step_2_ctx_t step2;
  sign_step_4_ctx_t step4;
  sign_step_5_ctx_t step5;
  sign_step_6_ctx_t step6;
  sign_step_7_ctx_t step7;
  sign_step_8_ctx_t step8;
  sign_step_9_ctx_t step9;
};

sign_ctx_t* sign_ctx_create(void) { return new sign_ctx_t(); }
void sign_ctx_destroy(sign_ctx_t* ctx) { delete ctx; }

error_t sign_validate_and_begin(job_mp_t& job, key_t& key, mem_t msg, party_idx_t sig_receiver,
                                const std::vector<std::vector<int>>& ot_role_map, sign_ctx_t& ctx) {
  int n = job.get_n_parties();
  int i = job.get_party_idx();

  if ((int)ot_role_map.size() != n) return coinbase::error(E_BADARG, "invalid ot_role_map: row count mismatch");
  for (int r = 0; r < n; r++) {
    if ((int)ot_role_map[r].size() != n) return coinbase::error(E_BADARG, "invalid ot_role_map: column count mismatch");
  }
  for (int r = 0; r < n; r++) {
    for (int c = 0; c < n; c++) {
      int role = ot_role_map[r][c];
      if (r == c) {
        if (role != ot_no_role) return coinbase::error(E_BADARG, "invalid ot_role_map: diagonal must be ot_no_role");
        continue;
      }
      if (role != ot_sender && role != ot_receiver)
        return coinbase::error(E_BADARG, "invalid ot_role_map: entries must be ot_sender or ot_receiver");
      int opp = ot_role_map[c][r];
      if ((role == ot_sender && opp != ot_receiver) || (role == ot_receiver && opp != ot_sender))
        return coinbase::error(E_BADARG, "invalid ot_role_map: roles must be anti-symmetric");
    }
  }

  auto& c = ctx.common;
  c.job = &job;
  c.key = &key;
  c.msg = msg;
  c.sig_receiver = sig_receiver;
  c.ot_role_map = &ot_role_map;
  c.n = n;
  c.i = i;
  c.peers_count = n;
  c.peer_index = i;
  c.curve = key.curve;
  c.theta = c.curve.order().get_bits_count() + kappa;

  if (key.x_share * c.curve.generator() != key.Qis.at(job.get_name(i)))
    return coinbase::error(E_BADARG, "x_share does not match Qi");
  if (SUM(key.Qis) != key.Q) return coinbase::error(E_BADARG, "Q does not match the sum of Qis");
  return SUCCESS;
}

// Step 1: 1st round of Pre-message — compute sid_i, c, h_consistency, s_i, Ei_gen, broadcast.
error_t sign_step_1(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s1 = ctx.step1;
  int n = c.n, i = c.i, theta = c.theta;
  const mod_t& q = c.curve.order();
  const auto& G = c.curve.generator();
  key_t& key = *c.key;
  mem_t msg = c.msg;

  s1.sid_i = std::make_unique<job_mp_t::uniform_msg_t<buf_t>>(c.job, crypto::gen_random_bitlen(SEC_P_COM));
  s1.h_consistency = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(c.job, buf256_t());
  s1.h_consistency->msg = crypto::sha256_t::hash(msg, key.Q, key.Qis);

  s1.s_i_val = bn_t::rand(q);
  s1.Ei_gen = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(c.job, s1.s_i_val * G);
  coinbase::crypto::commitment_t com(s1.sid_i->msg, job.get_pid(i));
  com.gen(s1.Ei_gen->msg, c.peer_index);
  s1.c = std::make_unique<job_mp_t::uniform_msg_t<buf_t>>(c.job, com.msg);
  s1.com_rand = com.rand;

  if (rv = job.plain_broadcast(*s1.sid_i, *s1.c, *s1.h_consistency)) return rv;
  return SUCCESS;
}

// Step 2: 2nd round Pre-message + first round signing — verify h_consistency, sid, h_gen, rho, pi_s, OT step1,
// broadcast.
error_t sign_step_2(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s1 = ctx.step1;
  auto& s2 = ctx.step2;
  int n = c.n, i = c.i, theta = c.theta;
  const mod_t& q = c.curve.order();
  key_t& key = *c.key;
  const auto& ot_role_map = *c.ot_role_map;

  for (int j = 0; j < n; j++) {
    if (j == i) continue;
    if (s1.h_consistency->received(j) != s1.h_consistency->msg) return coinbase::error(E_CRYPTO);
  }
  auto pids = job.get_pids();
  std::sort(pids.begin(), pids.end());
  std::vector<buf_t> sid_js(n);
  for (int j = 0; j < n; j++) sid_js[j] = (j == i) ? s1.sid_i->msg : s1.sid_i->received(j);
  s2.sid = crypto::sha256_t::hash(sid_js, pids);

  s2.h_gen = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(c.job, crypto::sha256_t::hash(s1.c->all_received()));
  s2.rho = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(c.job, s1.com_rand);
  s2.pi_s = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_dl_t>>(c.job, zk::uc_dl_t());
  s2.pi_s->prove(*s1.Ei_gen, s1.s_i_val, s2.sid, c.peers_count + c.peer_index);

  s2.ot.clear();
  for (int j = 0; j < n; j++) s2.ot.emplace_back(c.curve);
  s2.R_bits_i.resize(n);
  s2.R.resize(theta);
  for (int l = 0; l < theta; l++) s2.R[l].resize(n);
  for (int j = 0; j < n; j++) {
    int rid_s = (ot_role_map[i][j] == ot_sender) ? i : j;
    int rid_r = (ot_role_map[i][j] == ot_sender) ? j : i;
    s2.ot[j].base.sid = crypto::sha256_t::hash(s2.sid, rid_s, rid_r);
  }
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_sender) continue;
    if (rv = s2.ot[j].step1_S2R()) return rv;
  }

  party_set_t ot_receivers = ot_receivers_for(i, n, ot_role_map);
  auto ot_msg1 = job.inplace_msg<mpc::ot_protocol_pvw_ctx_t::msg1_t>([&s2](int j) { return s2.ot[j].msg1(); });
  if (rv = plain_broadcast_and_pairwise_message(job, ot_receivers, ot_msg1, *s2.h_gen, *s1.Ei_gen, *s2.rho, *s2.pi_s))
    return rv;
  return SUCCESS;
}

// Step 3: 2nd round of signing — verify commitments, E, R_bits, OT step2, broadcast.
error_t sign_step_3(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s1 = ctx.step1;
  auto& s2 = ctx.step2;
  int n = c.n, i = c.i, theta = c.theta;
  const mod_t& q = c.curve.order();
  const auto& ot_role_map = *c.ot_role_map;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (s2.h_gen->received(j) != s2.h_gen->msg) return coinbase::error(E_CRYPTO);
    if (rv = coinbase::crypto::commitment_t(s1.sid_i->received(j), job.get_pid(j))
                 .set(s2.rho->received(j), s1.c->received(j))
                 .open(s1.Ei_gen->received(j), j))
      return rv;
    if (rv = s2.pi_s->received(j).verify(s1.Ei_gen->received(j), s2.sid, c.peers_count + j)) return rv;
  }
  s2.E_i = s1.Ei_gen->all_received();
  s2.E = SUM(s2.E_i);

  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    s2.R_bits_i[j] = crypto::gen_random_bits(4 * theta);
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) s2.R[l][j][t] = s2.R_bits_i[j][l * 4 + t];
  }
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    if (rv = s2.ot[j].step2_R2S(s2.R_bits_i[j], q.get_bits_count())) return rv;
  }

  party_set_t ot_senders = ot_senders_for(i, n, ot_role_map);
  auto ot_msg2 = job.inplace_msg<mpc::ot_protocol_pvw_ctx_t::msg2_t>([&s2](int j) { return s2.ot[j].msg2(); });
  if (rv = plain_broadcast_and_pairwise_message(job, ot_senders, ot_msg2)) return rv;
  return SUCCESS;
}

// Step 4: 3rd round — k_i, rho_i, eK_i, eRHO_i, pi, delta, OT step3, broadcast.
error_t sign_step_4(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s2 = ctx.step2;
  auto& s4 = ctx.step4;
  int n = c.n, i = c.i, theta = c.theta;
  const mod_t& q = c.curve.order();
  key_t& key = *c.key;
  const auto& ot_role_map = *c.ot_role_map;
  const int n_uc_elgamal_com_proofs = 4;

  s4.k_i = bn_t::rand(q);
  s4.rho_i = bn_t::rand(q);
  s4.r_eK_i = bn_t::rand(q);
  s4.r_eRHO_i = bn_t::rand(q);
  s4.eK_i =
      std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(c.job, elg_com_t::commit(s2.E, s4.k_i).rand(s4.r_eK_i));
  s4.eRHO_i =
      std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(c.job, elg_com_t::commit(s2.E, s4.rho_i).rand(s4.r_eRHO_i));
  s4.pi_eK = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(c.job, zk::uc_elgamal_com_t());
  s4.pi_eRHO = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(c.job, zk::uc_elgamal_com_t());
  s4.pi_eK->prove(s2.E, s4.eK_i->msg, s4.k_i, s4.r_eK_i, s2.sid, n_uc_elgamal_com_proofs * i + 0);
  s4.pi_eRHO->prove(s2.E, s4.eRHO_i->msg, s4.rho_i, s4.r_eRHO_i, s2.sid, n_uc_elgamal_com_proofs * i + 1);
  s4.x_i = key.x_share;

  s4.delta.resize(theta * n);
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_sender) continue;
    bn_t a[] = {s4.rho_i, s4.k_i, s4.rho_i, s4.x_i};
    std::vector<bn_t> D(4 * theta);
    bn_t Delta[4];
    for (int t = 0; t < 4; t++) MODULO(q) Delta[t] = a[t] + a[t];
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) D[l * 4 + t] = Delta[t];
    std::vector<bn_t> X0, _X1;
    if (rv = s2.ot[j].step3_S2R(D, q, X0, _X1)) return rv;
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) MODULO(q) s4.delta[l * n + j][t] = X0[l * 4 + t] + a[t];
  }

  party_set_t ot_receivers = ot_receivers_for(i, n, ot_role_map);
  auto ot_msg3 =
      job.inplace_msg<mpc::ot_protocol_pvw_ctx_t::msg3_delta_t>([&s2](int j) { return s2.ot[j].msg3_delta(); });
  if (rv = plain_broadcast_and_pairwise_message(job, ot_receivers, ot_msg3, *s4.eK_i, *s4.eRHO_i, *s4.pi_eK,
                                                *s4.pi_eRHO))
    return rv;
  return SUCCESS;
}

// Step 5: 4th round — OT output_R, verify pi_eK/pi_eRHO, view, seed, v_theta, s[receiver], broadcast.
error_t sign_step_5(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s2 = ctx.step2;
  auto& s4 = ctx.step4;
  auto& s5 = ctx.step5;
  int n = c.n, i = c.i, theta = c.theta;
  const mod_t& q = c.curve.order();
  key_t& key = *c.key;
  const auto& ot_role_map = *c.ot_role_map;
  const int n_uc_elgamal_com_proofs = 4;

  s5.X.resize(theta * n);
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    std::vector<buf_t> X_bin;
    if (rv = s2.ot[j].output_R(4 * theta, X_bin)) return rv;
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) s5.X[l * n + j][t] = bn_t::from_bin(X_bin[l * 4 + t]);
  }

  s5.view.update(s2.E_i, s4.eK_i->all_received(), s4.eRHO_i->all_received(), s4.pi_eK->all_received(),
                 s4.pi_eRHO->all_received());
  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (rv = s4.pi_eK->received(j).verify(s2.E, s4.eK_i->received(j), s2.sid, n_uc_elgamal_com_proofs * j + 0))
      return rv;
    if (rv = s4.pi_eRHO->received(j).verify(s2.E, s4.eRHO_i->received(j), s2.sid, n_uc_elgamal_com_proofs * j + 1))
      return rv;
  }

  s5.seed = std::make_unique<job_mp_t::nonuniform_msg_t<buf256_t>>(c.job);
  s5.v_theta = std::make_unique<job_mp_t::nonuniform_msg_t<std::array<bn_t, 4>>>(c.job);
  s5.s_ot_sender.resize(n);
  s5.s_ot_receiver.resize(n);

  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    crypto::gen_random(s5.seed->msgs[j]);
    crypto::drbg_aes_ctr_t drbg(s5.seed->msgs[j]);
    bn_t a[] = {s4.k_i, s4.rho_i, s4.x_i, s4.rho_i};
    std::array<bn_t, 4> v[512];  // theta max
    for (int t = 0; t < 4; t++) {
      for (int l = 0; l < theta - 1; l++) v[l][t] = drbg.gen_bn(q);
      bn_t temp = 0;
      MODULO(q) {
        for (int l = 0; l < theta - 1; l++) {
          if (s2.R[l][j][t])
            temp += v[l][t];
          else
            temp -= v[l][t];
        }
      }
      MODULO(q) v[theta - 1][t] = s2.R[theta - 1][j][t] ? a[t] - temp : temp - a[t];
      bn_t sigma = drbg.gen_bn(q);
      bn_t sum = 0;
      MODULO(q) {
        for (int l = 0; l < theta; l++) sum += v[l][t] * s5.X[l * n + j][t];
        s5.s_ot_receiver[j][t] = sigma + sum;
      }
    }
    s5.v_theta->msgs[j] = v[theta - 1];
  }

  party_set_t ot_senders = ot_senders_for(i, n, ot_role_map);
  auto ot_part = job_mp_t::tie_msgs(*s5.seed, *s5.v_theta);
  if (rv = plain_broadcast_and_pairwise_message(job, ot_senders, ot_part)) return rv;
  return SUCCESS;
}

// Step 6: 5th round — s[sender], rho_k_i, rho_x_i, eRHO_K, eRHO_X, F_*, pi_*, broadcast.
error_t sign_step_6(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s2 = ctx.step2;
  auto& s4 = ctx.step4;
  auto& s5 = ctx.step5;
  auto& s6 = ctx.step6;
  int n = c.n, i = c.i, theta = c.theta;
  const mod_t& q = c.curve.order();
  key_t& key = *c.key;
  const auto& ot_role_map = *c.ot_role_map;
  const int n_uc_elgamal_com_proofs = 4;

  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_sender) continue;
    const std::array<bn_t, 4>& vt = s5.v_theta->received(j);
    for (int t = 0; t < 4; t++) {
      if (!q.is_in_range(vt[t])) return coinbase::error(E_CRYPTO, "invalid v_theta");
    }
    crypto::drbg_aes_ctr_t drbg(s5.seed->received(j));
    std::array<bn_t, 4> v[512];
    for (int t = 0; t < 4; t++) {
      for (int l = 0; l < theta - 1; l++) v[l][t] = drbg.gen_bn(q);
      v[theta - 1][t] = vt[t];
      bn_t sigma = drbg.gen_bn(q);
      bn_t sum = 0;
      MODULO(q) {
        for (int l = 0; l < theta; l++) sum -= v[l][t] * s4.delta[l * n + j][t];
        s5.s_ot_sender[j][t] = sum - sigma;
      }
    }
  }

  MODULO(q) {
    s6.rho_k_i = s4.rho_i * s4.k_i + SUM<bn_t>(n, [&](bn_t& sum, int j) {
                   if (i == j) return;
                   int role = ot_role_map[i][j];
                   sum += (role == ot_sender ? s5.s_ot_sender[j] : s5.s_ot_receiver[j])[0] +
                          (role == ot_sender ? s5.s_ot_sender[j] : s5.s_ot_receiver[j])[1];
                 });
    s6.rho_x_i = s4.rho_i * s4.x_i + SUM<bn_t>(n, [&](bn_t& sum, int j) {
                   if (i == j) return;
                   int role = ot_role_map[i][j];
                   sum += (role == ot_sender ? s5.s_ot_sender[j] : s5.s_ot_receiver[j])[2] +
                          (role == ot_sender ? s5.s_ot_sender[j] : s5.s_ot_receiver[j])[3];
                 });
  }

  s6.r_eRHO_K = bn_t::rand(q);
  s6.r_eRHO_X = bn_t::rand(q);
  s6.eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      c.job, elg_com_t::commit(s2.E, s6.rho_k_i).rand(s6.r_eRHO_K));
  s6.eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      c.job, elg_com_t::commit(s2.E, s6.rho_x_i).rand(s6.r_eRHO_X));
  s6.pi_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(c.job, zk::uc_elgamal_com_t());
  s6.pi_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(c.job, zk::uc_elgamal_com_t());
  s6.pi_eRHO_K->prove(s2.E, s6.eRHO_K->msg, s6.rho_k_i, s6.r_eRHO_K, s2.sid, n_uc_elgamal_com_proofs * i + 2);
  s6.pi_eRHO_X->prove(s2.E, s6.eRHO_X->msg, s6.rho_x_i, s6.r_eRHO_X, s2.sid, n_uc_elgamal_com_proofs * i + 3);

  elg_com_t eK = SUM(s4.eK_i->all_received());
  elg_com_t eX = elg_com_t(c.curve.generator(), s2.E + key.Q);
  s6.r_F_eRHO_K = bn_t::rand(q);
  s6.r_F_eRHO_X = bn_t::rand(q);
  s6.F_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      c.job, elg_com_t::rerand(s2.E, s4.rho_i * eK).rand(s6.r_F_eRHO_K));
  s6.F_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      c.job, elg_com_t::rerand(s2.E, s4.rho_i * eX).rand(s6.r_F_eRHO_X));
  const int n_elgamal_com_mult_proofs = 2;
  s6.pi_F_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_mult_t>>(c.job, zk::elgamal_com_mult_t());
  s6.pi_F_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_mult_t>>(c.job, zk::elgamal_com_mult_t());
  s6.pi_F_eRHO_K->prove(s2.E, eK, s4.eRHO_i->msg, s6.F_eRHO_K->msg, s4.r_eRHO_i, s6.r_F_eRHO_K, s4.rho_i, s2.sid,
                        n_elgamal_com_mult_proofs * i + 0);
  s6.pi_F_eRHO_X->prove(s2.E, eX, s4.eRHO_i->msg, s6.F_eRHO_X->msg, s4.r_eRHO_i, s6.r_F_eRHO_X, s4.rho_i, s2.sid,
                        n_elgamal_com_mult_proofs * i + 1);

  if (rv = job.plain_broadcast(*s6.eRHO_K, *s6.pi_eRHO_K, *s6.eRHO_X, *s6.pi_eRHO_X, *s6.F_eRHO_K, *s6.pi_F_eRHO_K,
                               *s6.F_eRHO_X, *s6.pi_F_eRHO_X))
    return rv;
  return SUCCESS;
}

// Step 7: 6th round — view.update, h, verify, Y, Z_*, pi_Z, broadcast.
error_t sign_step_7(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s2 = ctx.step2;
  auto& s4 = ctx.step4;
  auto& s5 = ctx.step5;
  auto& s6 = ctx.step6;
  auto& s7 = ctx.step7;
  int n = c.n, i = c.i;
  const mod_t& q = c.curve.order();
  const int n_uc_elgamal_com_proofs = 4;
  const int n_elgamal_com_mult_proofs = 2;
  const int n_elgamal_mult_private_scalar_proofs = 2;

  s5.view.update(s6.eRHO_K->all_received(), s6.pi_eRHO_K->all_received(), s6.eRHO_X->all_received(),
                 s6.pi_eRHO_X->all_received(), s6.F_eRHO_K->all_received(), s6.pi_F_eRHO_K->all_received(),
                 s6.F_eRHO_X->all_received(), s6.pi_F_eRHO_X->all_received());
  s7.h = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(c.job, s5.view.final());

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (rv = s6.pi_F_eRHO_K->received(j).verify(s2.E, SUM(s4.eK_i->all_received()), s4.eRHO_i->received(j),
                                                s6.F_eRHO_K->received(j), s2.sid, n_elgamal_com_mult_proofs * j + 0))
      return rv;
    if (rv = s6.pi_F_eRHO_X->received(j).verify(s2.E, elg_com_t(c.curve.generator(), s2.E + c.key->Q),
                                                s4.eRHO_i->received(j), s6.F_eRHO_X->received(j), s2.sid,
                                                n_elgamal_com_mult_proofs * j + 1))
      return rv;
    if (rv = s6.pi_eRHO_K->received(j).verify(s2.E, s6.eRHO_K->received(j), s2.sid, n_uc_elgamal_com_proofs * j + 2))
      return rv;
    if (rv = s6.pi_eRHO_X->received(j).verify(s2.E, s6.eRHO_X->received(j), s2.sid, n_uc_elgamal_com_proofs * j + 3))
      return rv;
  }

  s7.Y_eRHO_K = SUM(s6.F_eRHO_K->all_received()) - SUM(s6.eRHO_K->all_received());
  s7.Y_eRHO_X = SUM(s6.F_eRHO_X->all_received()) - SUM(s6.eRHO_X->all_received());
  s7.r_Z_eRHO_K = bn_t::rand(q);
  s7.r_Z_eRHO_X = bn_t::rand(q);
  s7.o_Z_eRHO_K = bn_t::rand(q);
  s7.o_Z_eRHO_X = bn_t::rand(q);
  s7.Z_eRHO_K_i = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      c.job, elg_com_t::rerand(s2.E, s7.o_Z_eRHO_K * s7.Y_eRHO_K).rand(s7.r_Z_eRHO_K));
  s7.Z_eRHO_X_i = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      c.job, elg_com_t::rerand(s2.E, s7.o_Z_eRHO_X * s7.Y_eRHO_X).rand(s7.r_Z_eRHO_X));
  s7.pi_Z_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>>(
      c.job, zk::uc_elgamal_com_mult_private_scalar_t());
  s7.pi_Z_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>>(
      c.job, zk::uc_elgamal_com_mult_private_scalar_t());
  s7.pi_Z_eRHO_K->prove(s2.E, s7.Y_eRHO_K, s7.Z_eRHO_K_i->msg, s7.r_Z_eRHO_K, s7.o_Z_eRHO_K, s2.sid,
                        n_elgamal_mult_private_scalar_proofs * i + 0);
  s7.pi_Z_eRHO_X->prove(s2.E, s7.Y_eRHO_X, s7.Z_eRHO_X_i->msg, s7.r_Z_eRHO_X, s7.o_Z_eRHO_X, s2.sid,
                        n_elgamal_mult_private_scalar_proofs * i + 1);

  if (rv = job.plain_broadcast(*s7.h, *s7.Z_eRHO_K_i, *s7.pi_Z_eRHO_K, *s7.Z_eRHO_X_i, *s7.pi_Z_eRHO_X)) return rv;
  return SUCCESS;
}

// Step 8: 7th round — verify h, pi_Z, h2, Z, W_*, pi_W, K_i, pi_K, broadcast.
error_t sign_step_8(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s1 = ctx.step1;
  auto& s2 = ctx.step2;
  auto& s4 = ctx.step4;
  auto& s7 = ctx.step7;
  auto& s8 = ctx.step8;
  int n = c.n, i = c.i;
  const int n_dh_proofs = 2;
  const int n_elgamal_com_pub_share_equ_proofs = 3;
  const int n_elgamal_mult_private_scalar_proofs = 2;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (s7.h->msg != s7.h->received(j)) return coinbase::error(E_CRYPTO);
    if (rv = s7.pi_Z_eRHO_K->received(j).verify(s2.E, s7.Y_eRHO_K, s7.Z_eRHO_K_i->received(j), s2.sid,
                                                n_elgamal_mult_private_scalar_proofs * j + 0))
      return rv;
    if (rv = s7.pi_Z_eRHO_X->received(j).verify(s2.E, s7.Y_eRHO_X, s7.Z_eRHO_X_i->received(j), s2.sid,
                                                n_elgamal_mult_private_scalar_proofs * j + 1))
      return rv;
  }

  s8.h2 = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(
      c.job, crypto::sha256_t::hash(s7.Z_eRHO_K_i->all_received(), s7.pi_Z_eRHO_K->all_received(),
                                    s7.Z_eRHO_X_i->all_received(), s7.pi_Z_eRHO_X->all_received(), s7.h->msg));
  s8.Z_eRHO_K = SUM(s7.Z_eRHO_K_i->all_received());
  s8.Z_eRHO_X = SUM(s7.Z_eRHO_X_i->all_received());

  s8.W_eRHO_K_i = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(c.job, s1.s_i_val * s8.Z_eRHO_K.L);
  s8.W_eRHO_X_i = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(c.job, s1.s_i_val * s8.Z_eRHO_X.L);
  s8.pi_W_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::dh_t>>(c.job, zk::dh_t());
  s8.pi_W_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::dh_t>>(c.job, zk::dh_t());
  s8.pi_W_eRHO_K->prove(s8.Z_eRHO_K.L, s2.E_i[i], s8.W_eRHO_K_i->msg, s1.s_i_val, s2.sid, n_dh_proofs * i + 0);
  s8.pi_W_eRHO_X->prove(s8.Z_eRHO_X.L, s2.E_i[i], s8.W_eRHO_X_i->msg, s1.s_i_val, s2.sid, n_dh_proofs * i + 1);
  s8.K_i = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(c.job, s4.k_i * c.curve.generator());
  s8.pi_K = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>>(
      c.job, zk::elgamal_com_pub_share_equ_t());
  s8.pi_K->prove(s2.E, s8.K_i->msg, s4.eK_i->msg, s4.r_eK_i, s2.sid, n_elgamal_com_pub_share_equ_proofs * i + 0);

  if (rv = job.plain_broadcast(*s8.W_eRHO_K_i, *s8.pi_W_eRHO_K, *s8.W_eRHO_X_i, *s8.pi_W_eRHO_X, *s8.K_i, *s8.pi_K,
                               *s8.h2))
    return rv;
  return SUCCESS;
}

// Step 9: 8th round — verify h2, pi_W, pi_K, K, r, W check, m, beta, eB, pi_R_*, rho_k, send_message_all_to_one.
error_t sign_step_9(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  auto& c = ctx.common;
  auto& s2 = ctx.step2;
  auto& s4 = ctx.step4;
  auto& s6 = ctx.step6;
  auto& s8 = ctx.step8;
  auto& s9 = ctx.step9;
  int n = c.n, i = c.i;
  key_t& key = *c.key;
  const mod_t& q = c.curve.order();
  const int n_elgamal_com_pub_share_equ_proofs = 3;
  const int n_dh_proofs = 2;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (s8.h2->msg != s8.h2->received(j)) return coinbase::error(E_CRYPTO);
    if (rv = s8.pi_W_eRHO_K->received(j).verify(s8.Z_eRHO_K.L, s2.E_i[j], s8.W_eRHO_K_i->received(j), s2.sid,
                                                n_dh_proofs * j + 0))
      return rv;
    if (rv = s8.pi_W_eRHO_X->received(j).verify(s8.Z_eRHO_X.L, s2.E_i[j], s8.W_eRHO_X_i->received(j), s2.sid,
                                                n_dh_proofs * j + 1))
      return rv;
    if (rv = s8.pi_K->received(j).verify(s2.E, s8.K_i->received(j), s4.eK_i->received(j), s2.sid,
                                         n_elgamal_com_pub_share_equ_proofs * j + 0))
      return rv;
  }

  s9.K = SUM(s8.K_i->all_received());
  bn_t r_tag = s9.K.get_x();
  s9.r = r_tag % q;
  ecc_point_t W_eRHO_K = SUM(s8.W_eRHO_K_i->all_received());
  ecc_point_t W_eRHO_X = SUM(s8.W_eRHO_X_i->all_received());
  if (W_eRHO_K != s8.Z_eRHO_K.R) return coinbase::error(E_CRYPTO);
  if (W_eRHO_X != s8.Z_eRHO_X.R) return coinbase::error(E_CRYPTO);

  s9.m = curve_msg_to_bn(c.msg, c.curve);
  s9.beta = std::make_unique<job_mp_t::uniform_msg_t<bn_t>>(c.job, bn_t());
  MODULO(q) {
    s9.r_rho_x = s9.r * s6.rho_x_i;
    s9.rho_m = s9.m * s4.rho_i;
    s9.beta->msg = s9.r_rho_x + s9.rho_m;
    s9.r_eR_RHO_X = s9.r * s6.r_eRHO_X;
    s9.r_eR_RHO_M = s9.m * s4.r_eRHO_i;
    s9.r_eB = s9.r_eR_RHO_X + s9.r_eR_RHO_M;
  }
  s9.eB.resize(n);
  for (int j = 0; j < n; j++) {
    elg_com_t eR_RHO_X = s9.r * s6.eRHO_X->received(j);
    elg_com_t eRHO_M = s9.m * s4.eRHO_i->received(j);
    s9.eB[j] = eR_RHO_X + eRHO_M;
  }
  s9.r_eRHO_K_val = s6.r_eRHO_K;
  s9.pi_R_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>>(
      c.job, zk::elgamal_com_pub_share_equ_t());
  s9.pi_R_eB = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>>(
      c.job, zk::elgamal_com_pub_share_equ_t());
  ecc_point_t RHO_K = s6.rho_k_i * c.curve.generator();
  ecc_point_t B = s9.beta->msg * c.curve.generator();
  s9.pi_R_eRHO_K->prove(s2.E, RHO_K, s6.eRHO_K->msg, s9.r_eRHO_K_val, s2.sid,
                        n_elgamal_com_pub_share_equ_proofs * i + 1);
  s9.pi_R_eB->prove(s2.E, B, s9.eB[i], s9.r_eB, s2.sid, n_elgamal_com_pub_share_equ_proofs * i + 2);
  s9.rho_k = std::make_unique<job_mp_t::uniform_msg_t<bn_t>>(c.job, s6.rho_k_i);

  if (rv = job.send_message_all_to_one(c.sig_receiver, *s9.rho_k, *s9.pi_R_eRHO_K, *s9.beta, *s9.pi_R_eB)) return rv;
  return SUCCESS;
}

// Step 10: Output — sig_receiver verifies and computes sig.
error_t sign_step_10(job_mp_t& job, sign_ctx_t& ctx, buf_t& sig) {
  error_t rv;
  auto& c = ctx.common;
  auto& s2 = ctx.step2;
  auto& s6 = ctx.step6;
  auto& s9 = ctx.step9;
  int n = c.n, i = c.i;
  key_t& key = *c.key;
  const mod_t& q = c.curve.order();
  const int n_elgamal_com_pub_share_equ_proofs = 3;

  if (!job.is_party_idx(c.sig_receiver)) return SUCCESS;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    ecc_point_t RHO_K = s9.rho_k->received(j) * c.curve.generator();
    ecc_point_t B = s9.beta->received(j) * c.curve.generator();
    if (rv = s9.pi_R_eRHO_K->received(j).verify(s2.E, RHO_K, s6.eRHO_K->received(j), s2.sid,
                                                n_elgamal_com_pub_share_equ_proofs * j + 1))
      return rv;
    if (rv = s9.pi_R_eB->received(j).verify(s2.E, B, s9.eB[j], s2.sid, n_elgamal_com_pub_share_equ_proofs * j + 2))
      return rv;
  }

  bn_t sum_rho_k = SUM(s9.rho_k->all_received(), q);
  bn_t sum_beta = SUM(s9.beta->all_received(), q);
  bn_t s;
  MODULO(q) s = sum_beta / sum_rho_k;
  bn_t s_reduced = q - s;
  if (s_reduced < s) s = s_reduced;
  sig = crypto::ecdsa_signature_t(c.curve, s9.r, s).to_der();
  crypto::ecc_pub_key_t pub(key.Q);
  if (rv = pub.verify(c.msg, sig)) return rv;
  return SUCCESS;
}

}  // namespace coinbase::mpc::ecdsampc
