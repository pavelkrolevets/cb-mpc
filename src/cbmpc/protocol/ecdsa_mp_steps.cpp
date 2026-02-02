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

error_t dkg(job_mp_t& job, ecurve_t curve, key_t& key, buf_t& sid) {
  return eckey::key_share_mp_t::dkg(job, curve, key, sid);
}

error_t refresh(job_mp_t& job, buf_t& sid, key_t& key, key_t& new_key) {
  return eckey::key_share_mp_t::refresh(job, sid, key, new_key);
}

error_t threshold_dkg(job_mp_t& job, ecurve_t curve, buf_t& sid, const crypto::ss::ac_t ac,
                      const party_set_t& quorum_party_set, key_t& key) {
  return eckey::key_share_mp_t::threshold_dkg(job, curve, sid, ac, quorum_party_set, key);
}

error_t threshold_refresh(job_mp_t& job, ecurve_t curve, buf_t& sid, const crypto::ss::ac_t ac,
                          const party_set_t& quorum_party_set, key_t& key, key_t& new_key) {
  return eckey::key_share_mp_t::threshold_refresh(job, curve, sid, ac, quorum_party_set, key, new_key);
}

// Context for step-wise sign. Full definition here; opaque in ecdsa_mp_steps.h.
struct sign_ctx_t {
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

  // Message containers (owned; created with job in sign_begin / step 1)
  std::unique_ptr<job_mp_t::uniform_msg_t<buf_t>> sid_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf_t>> c;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h_consistency;
  bn_t s_i_val;
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> Ei_gen;
  buf256_t com_rand;

  buf_t sid;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h_gen;
  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> rho;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_dl_t>> pi_s;
  std::vector<mpc::ot_protocol_pvw_ctx_t> ot;
  std::vector<coinbase::bits_t> R_bits_i;
  std::vector<std::vector<std::array<bool, 4>>> R;  // theta x n
  std::vector<ecc_point_t> E_i;
  ecc_point_t E;

  std::vector<std::array<bn_t, 4>> delta;  // flattened theta*n, index l*n+j
  std::vector<std::array<bn_t, 4>> X;      // flattened theta*n
  crypto::sha256_t view;

  bn_t k_i{}, rho_i{}, r_eK_i{}, r_eRHO_i{};
  bn_t x_i{};
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> eK_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> eRHO_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>> pi_eK;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>> pi_eRHO;

  std::unique_ptr<job_mp_t::nonuniform_msg_t<buf256_t>> seed;
  std::unique_ptr<job_mp_t::nonuniform_msg_t<std::array<bn_t, 4>>> v_theta;
  std::vector<std::array<bn_t, 4>> s_ot_sender;    // n
  std::vector<std::array<bn_t, 4>> s_ot_receiver;  // n

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

  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h;
  elg_com_t Y_eRHO_K{}, Y_eRHO_X{};
  bn_t r_Z_eRHO_K{}, r_Z_eRHO_X{}, o_Z_eRHO_K{}, o_Z_eRHO_X{};
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> Z_eRHO_K_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<elg_com_t>> Z_eRHO_X_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>> pi_Z_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>> pi_Z_eRHO_X;

  std::unique_ptr<job_mp_t::uniform_msg_t<buf256_t>> h2;
  elg_com_t Z_eRHO_K{}, Z_eRHO_X{};
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> W_eRHO_K_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> W_eRHO_X_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::dh_t>> pi_W_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::dh_t>> pi_W_eRHO_X;
  std::unique_ptr<job_mp_t::uniform_msg_t<ecc_point_t>> K_i;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>> pi_K;

  ecc_point_t K{};
  bn_t r{};
  bn_t m{};
  std::unique_ptr<job_mp_t::uniform_msg_t<bn_t>> beta;
  std::vector<elg_com_t> eB;
  bn_t r_rho_x{}, rho_m{}, r_eR_RHO_X{}, r_eR_RHO_M{}, r_eB{};
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>> pi_R_eRHO_K;
  std::unique_ptr<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>> pi_R_eB;
  std::unique_ptr<job_mp_t::uniform_msg_t<bn_t>> rho_k;
  bn_t r_eRHO_K_val{};  // for pi_R_eRHO_K.prove
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

  ctx.job = &job;
  ctx.key = &key;
  ctx.msg = msg;
  ctx.sig_receiver = sig_receiver;
  ctx.ot_role_map = &ot_role_map;
  ctx.n = n;
  ctx.i = i;
  ctx.peers_count = n;
  ctx.peer_index = i;
  ctx.curve = key.curve;
  ctx.theta = ctx.curve.order().get_bits_count() + kappa;

  if (key.x_share * ctx.curve.generator() != key.Qis.at(job.get_name(i)))
    return coinbase::error(E_BADARG, "x_share does not match Qi");
  if (SUM(key.Qis) != key.Q) return coinbase::error(E_BADARG, "Q does not match the sum of Qis");
  return SUCCESS;
}

// Step 1: 1st round of Pre-message — compute sid_i, c, h_consistency, s_i, Ei_gen, broadcast.
error_t sign_step_1(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i, theta = ctx.theta;
  const mod_t& q = ctx.curve.order();
  const auto& G = ctx.curve.generator();
  key_t& key = *ctx.key;
  mem_t msg = ctx.msg;

  ctx.sid_i = std::make_unique<job_mp_t::uniform_msg_t<buf_t>>(ctx.job, crypto::gen_random_bitlen(SEC_P_COM));
  ctx.h_consistency = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(ctx.job, buf256_t());
  ctx.h_consistency->msg = crypto::sha256_t::hash(msg, key.Q, key.Qis);

  ctx.s_i_val = bn_t::rand(q);
  ctx.Ei_gen = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(ctx.job, ctx.s_i_val * G);
  coinbase::crypto::commitment_t com(ctx.sid_i->msg, job.get_pid(i));
  com.gen(ctx.Ei_gen->msg, ctx.peer_index);
  ctx.c = std::make_unique<job_mp_t::uniform_msg_t<buf_t>>(ctx.job, com.msg);
  ctx.com_rand = com.rand;

  if (rv = job.plain_broadcast(*ctx.sid_i, *ctx.c, *ctx.h_consistency)) return rv;
  return SUCCESS;
}

// Step 2: 2nd round Pre-message + first round signing — verify h_consistency, sid, h_gen, rho, pi_s, OT step1,
// broadcast.
error_t sign_step_2(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i, theta = ctx.theta;
  const mod_t& q = ctx.curve.order();
  key_t& key = *ctx.key;
  const auto& ot_role_map = *ctx.ot_role_map;

  for (int j = 0; j < n; j++) {
    if (j == i) continue;
    if (ctx.h_consistency->received(j) != ctx.h_consistency->msg) return coinbase::error(E_CRYPTO);
  }
  auto pids = job.get_pids();
  std::sort(pids.begin(), pids.end());
  std::vector<buf_t> sid_js(n);
  for (int j = 0; j < n; j++) sid_js[j] = (j == i) ? ctx.sid_i->msg : ctx.sid_i->received(j);
  ctx.sid = crypto::sha256_t::hash(sid_js, pids);

  ctx.h_gen =
      std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(ctx.job, crypto::sha256_t::hash(ctx.c->all_received()));
  ctx.rho = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(ctx.job, ctx.com_rand);
  ctx.pi_s = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_dl_t>>(ctx.job, zk::uc_dl_t());
  ctx.pi_s->prove(*ctx.Ei_gen, ctx.s_i_val, ctx.sid, ctx.peers_count + ctx.peer_index);

  ctx.ot.clear();
  for (int j = 0; j < n; j++) ctx.ot.emplace_back(ctx.curve);
  ctx.R_bits_i.resize(n);
  ctx.R.resize(theta);
  for (int l = 0; l < theta; l++) ctx.R[l].resize(n);
  for (int j = 0; j < n; j++) {
    int rid_s = (ot_role_map[i][j] == ot_sender) ? i : j;
    int rid_r = (ot_role_map[i][j] == ot_sender) ? j : i;
    ctx.ot[j].base.sid = crypto::sha256_t::hash(ctx.sid, rid_s, rid_r);
  }
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_sender) continue;
    if (rv = ctx.ot[j].step1_S2R()) return rv;
  }

  party_set_t ot_receivers = ot_receivers_for(i, n, ot_role_map);
  auto ot_msg1 = job.inplace_msg<mpc::ot_protocol_pvw_ctx_t::msg1_t>([&ctx](int j) { return ctx.ot[j].msg1(); });
  if (rv = plain_broadcast_and_pairwise_message(job, ot_receivers, ot_msg1, *ctx.h_gen, *ctx.Ei_gen, *ctx.rho,
                                                *ctx.pi_s))
    return rv;
  return SUCCESS;
}

// Step 3: 2nd round of signing — verify commitments, E, R_bits, OT step2, broadcast.
error_t sign_step_3(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i, theta = ctx.theta;
  const mod_t& q = ctx.curve.order();
  const auto& ot_role_map = *ctx.ot_role_map;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (ctx.h_gen->received(j) != ctx.h_gen->msg) return coinbase::error(E_CRYPTO);
    if (rv = coinbase::crypto::commitment_t(ctx.sid_i->received(j), job.get_pid(j))
                 .set(ctx.rho->received(j), ctx.c->received(j))
                 .open(ctx.Ei_gen->received(j), j))
      return rv;
    if (rv = ctx.pi_s->received(j).verify(ctx.Ei_gen->received(j), ctx.sid, ctx.peers_count + j)) return rv;
  }
  ctx.E_i = ctx.Ei_gen->all_received();
  ctx.E = SUM(ctx.E_i);

  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    ctx.R_bits_i[j] = crypto::gen_random_bits(4 * theta);
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) ctx.R[l][j][t] = ctx.R_bits_i[j][l * 4 + t];
  }
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    if (rv = ctx.ot[j].step2_R2S(ctx.R_bits_i[j], q.get_bits_count())) return rv;
  }

  party_set_t ot_senders = ot_senders_for(i, n, ot_role_map);
  auto ot_msg2 = job.inplace_msg<mpc::ot_protocol_pvw_ctx_t::msg2_t>([&ctx](int j) { return ctx.ot[j].msg2(); });
  if (rv = plain_broadcast_and_pairwise_message(job, ot_senders, ot_msg2)) return rv;
  return SUCCESS;
}

// Step 4: 3rd round — k_i, rho_i, eK_i, eRHO_i, pi, delta, OT step3, broadcast.
error_t sign_step_4(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i, theta = ctx.theta;
  const mod_t& q = ctx.curve.order();
  key_t& key = *ctx.key;
  const auto& ot_role_map = *ctx.ot_role_map;
  const int n_uc_elgamal_com_proofs = 4;

  ctx.k_i = bn_t::rand(q);
  ctx.rho_i = bn_t::rand(q);
  ctx.r_eK_i = bn_t::rand(q);
  ctx.r_eRHO_i = bn_t::rand(q);
  ctx.eK_i =
      std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(ctx.job, elg_com_t::commit(ctx.E, ctx.k_i).rand(ctx.r_eK_i));
  ctx.eRHO_i = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::commit(ctx.E, ctx.rho_i).rand(ctx.r_eRHO_i));
  ctx.pi_eK = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(ctx.job, zk::uc_elgamal_com_t());
  ctx.pi_eRHO = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(ctx.job, zk::uc_elgamal_com_t());
  ctx.pi_eK->prove(ctx.E, ctx.eK_i->msg, ctx.k_i, ctx.r_eK_i, ctx.sid, n_uc_elgamal_com_proofs * i + 0);
  ctx.pi_eRHO->prove(ctx.E, ctx.eRHO_i->msg, ctx.rho_i, ctx.r_eRHO_i, ctx.sid, n_uc_elgamal_com_proofs * i + 1);
  ctx.x_i = key.x_share;

  ctx.delta.resize(theta * n);
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_sender) continue;
    bn_t a[] = {ctx.rho_i, ctx.k_i, ctx.rho_i, ctx.x_i};
    std::vector<bn_t> D(4 * theta);
    bn_t Delta[4];
    for (int t = 0; t < 4; t++) MODULO(q) Delta[t] = a[t] + a[t];
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) D[l * 4 + t] = Delta[t];
    std::vector<bn_t> X0, _X1;
    if (rv = ctx.ot[j].step3_S2R(D, q, X0, _X1)) return rv;
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) MODULO(q) ctx.delta[l * n + j][t] = X0[l * 4 + t] + a[t];
  }

  party_set_t ot_receivers = ot_receivers_for(i, n, ot_role_map);
  auto ot_msg3 =
      job.inplace_msg<mpc::ot_protocol_pvw_ctx_t::msg3_delta_t>([&ctx](int j) { return ctx.ot[j].msg3_delta(); });
  if (rv = plain_broadcast_and_pairwise_message(job, ot_receivers, ot_msg3, *ctx.eK_i, *ctx.eRHO_i, *ctx.pi_eK,
                                                *ctx.pi_eRHO))
    return rv;
  return SUCCESS;
}

// Step 5: 4th round — OT output_R, verify pi_eK/pi_eRHO, view, seed, v_theta, s[receiver], broadcast.
error_t sign_step_5(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i, theta = ctx.theta;
  const mod_t& q = ctx.curve.order();
  key_t& key = *ctx.key;
  const auto& ot_role_map = *ctx.ot_role_map;
  const int n_uc_elgamal_com_proofs = 4;

  ctx.X.resize(theta * n);
  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    std::vector<buf_t> X_bin;
    if (rv = ctx.ot[j].output_R(4 * theta, X_bin)) return rv;
    for (int l = 0; l < theta; l++)
      for (int t = 0; t < 4; t++) ctx.X[l * n + j][t] = bn_t::from_bin(X_bin[l * 4 + t]);
  }

  ctx.view.update(ctx.E_i, ctx.eK_i->all_received(), ctx.eRHO_i->all_received(), ctx.pi_eK->all_received(),
                  ctx.pi_eRHO->all_received());
  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (rv = ctx.pi_eK->received(j).verify(ctx.E, ctx.eK_i->received(j), ctx.sid, n_uc_elgamal_com_proofs * j + 0))
      return rv;
    if (rv = ctx.pi_eRHO->received(j).verify(ctx.E, ctx.eRHO_i->received(j), ctx.sid, n_uc_elgamal_com_proofs * j + 1))
      return rv;
  }

  ctx.seed = std::make_unique<job_mp_t::nonuniform_msg_t<buf256_t>>(ctx.job);
  ctx.v_theta = std::make_unique<job_mp_t::nonuniform_msg_t<std::array<bn_t, 4>>>(ctx.job);
  ctx.s_ot_sender.resize(n);
  ctx.s_ot_receiver.resize(n);

  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_receiver) continue;
    crypto::gen_random(ctx.seed->msgs[j]);
    crypto::drbg_aes_ctr_t drbg(ctx.seed->msgs[j]);
    bn_t a[] = {ctx.k_i, ctx.rho_i, ctx.x_i, ctx.rho_i};
    std::array<bn_t, 4> v[512];  // theta max
    for (int t = 0; t < 4; t++) {
      for (int l = 0; l < theta - 1; l++) v[l][t] = drbg.gen_bn(q);
      bn_t temp = 0;
      MODULO(q) {
        for (int l = 0; l < theta - 1; l++) {
          if (ctx.R[l][j][t])
            temp += v[l][t];
          else
            temp -= v[l][t];
        }
      }
      MODULO(q) v[theta - 1][t] = ctx.R[theta - 1][j][t] ? a[t] - temp : temp - a[t];
      bn_t sigma = drbg.gen_bn(q);
      bn_t sum = 0;
      MODULO(q) {
        for (int l = 0; l < theta; l++) sum += v[l][t] * ctx.X[l * n + j][t];
        ctx.s_ot_receiver[j][t] = sigma + sum;
      }
    }
    ctx.v_theta->msgs[j] = v[theta - 1];
  }

  party_set_t ot_senders = ot_senders_for(i, n, ot_role_map);
  auto ot_part = job_mp_t::tie_msgs(*ctx.seed, *ctx.v_theta);
  if (rv = plain_broadcast_and_pairwise_message(job, ot_senders, ot_part)) return rv;
  return SUCCESS;
}

// Step 6: 5th round — s[sender], rho_k_i, rho_x_i, eRHO_K, eRHO_X, F_*, pi_*, broadcast.
error_t sign_step_6(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i, theta = ctx.theta;
  const mod_t& q = ctx.curve.order();
  key_t& key = *ctx.key;
  const auto& ot_role_map = *ctx.ot_role_map;
  const int n_uc_elgamal_com_proofs = 4;

  for (int j = 0; j < n; j++) {
    if (ot_role_map[i][j] != ot_sender) continue;
    const std::array<bn_t, 4>& vt = ctx.v_theta->received(j);
    for (int t = 0; t < 4; t++) {
      if (!q.is_in_range(vt[t])) return coinbase::error(E_CRYPTO, "invalid v_theta");
    }
    crypto::drbg_aes_ctr_t drbg(ctx.seed->received(j));
    std::array<bn_t, 4> v[512];
    for (int t = 0; t < 4; t++) {
      for (int l = 0; l < theta - 1; l++) v[l][t] = drbg.gen_bn(q);
      v[theta - 1][t] = vt[t];
      bn_t sigma = drbg.gen_bn(q);
      bn_t sum = 0;
      MODULO(q) {
        for (int l = 0; l < theta; l++) sum -= v[l][t] * ctx.delta[l * n + j][t];
        ctx.s_ot_sender[j][t] = sum - sigma;
      }
    }
  }

  MODULO(q) {
    ctx.rho_k_i = ctx.rho_i * ctx.k_i + SUM<bn_t>(n, [&](bn_t& sum, int j) {
                    if (i == j) return;
                    int role = ot_role_map[i][j];
                    sum += (role == ot_sender ? ctx.s_ot_sender[j] : ctx.s_ot_receiver[j])[0] +
                           (role == ot_sender ? ctx.s_ot_sender[j] : ctx.s_ot_receiver[j])[1];
                  });
    ctx.rho_x_i = ctx.rho_i * ctx.x_i + SUM<bn_t>(n, [&](bn_t& sum, int j) {
                    if (i == j) return;
                    int role = ot_role_map[i][j];
                    sum += (role == ot_sender ? ctx.s_ot_sender[j] : ctx.s_ot_receiver[j])[2] +
                           (role == ot_sender ? ctx.s_ot_sender[j] : ctx.s_ot_receiver[j])[3];
                  });
  }

  ctx.r_eRHO_K = bn_t::rand(q);
  ctx.r_eRHO_X = bn_t::rand(q);
  ctx.eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::commit(ctx.E, ctx.rho_k_i).rand(ctx.r_eRHO_K));
  ctx.eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::commit(ctx.E, ctx.rho_x_i).rand(ctx.r_eRHO_X));
  ctx.pi_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(ctx.job, zk::uc_elgamal_com_t());
  ctx.pi_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_t>>(ctx.job, zk::uc_elgamal_com_t());
  ctx.pi_eRHO_K->prove(ctx.E, ctx.eRHO_K->msg, ctx.rho_k_i, ctx.r_eRHO_K, ctx.sid, n_uc_elgamal_com_proofs * i + 2);
  ctx.pi_eRHO_X->prove(ctx.E, ctx.eRHO_X->msg, ctx.rho_x_i, ctx.r_eRHO_X, ctx.sid, n_uc_elgamal_com_proofs * i + 3);

  elg_com_t eK = SUM(ctx.eK_i->all_received());
  elg_com_t eX = elg_com_t(ctx.curve.generator(), ctx.E + key.Q);
  ctx.r_F_eRHO_K = bn_t::rand(q);
  ctx.r_F_eRHO_X = bn_t::rand(q);
  ctx.F_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::rerand(ctx.E, ctx.rho_i * eK).rand(ctx.r_F_eRHO_K));
  ctx.F_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::rerand(ctx.E, ctx.rho_i * eX).rand(ctx.r_F_eRHO_X));
  const int n_elgamal_com_mult_proofs = 2;
  ctx.pi_F_eRHO_K =
      std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_mult_t>>(ctx.job, zk::elgamal_com_mult_t());
  ctx.pi_F_eRHO_X =
      std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_mult_t>>(ctx.job, zk::elgamal_com_mult_t());
  ctx.pi_F_eRHO_K->prove(ctx.E, eK, ctx.eRHO_i->msg, ctx.F_eRHO_K->msg, ctx.r_eRHO_i, ctx.r_F_eRHO_K, ctx.rho_i,
                         ctx.sid, n_elgamal_com_mult_proofs * i + 0);
  ctx.pi_F_eRHO_X->prove(ctx.E, eX, ctx.eRHO_i->msg, ctx.F_eRHO_X->msg, ctx.r_eRHO_i, ctx.r_F_eRHO_X, ctx.rho_i,
                         ctx.sid, n_elgamal_com_mult_proofs * i + 1);

  if (rv = job.plain_broadcast(*ctx.eRHO_K, *ctx.pi_eRHO_K, *ctx.eRHO_X, *ctx.pi_eRHO_X, *ctx.F_eRHO_K,
                               *ctx.pi_F_eRHO_K, *ctx.F_eRHO_X, *ctx.pi_F_eRHO_X))
    return rv;
  return SUCCESS;
}

// Step 7: 6th round — view.update, h, verify, Y, Z_*, pi_Z, broadcast.
error_t sign_step_7(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i;
  const mod_t& q = ctx.curve.order();
  const int n_uc_elgamal_com_proofs = 4;
  const int n_elgamal_com_mult_proofs = 2;
  const int n_elgamal_mult_private_scalar_proofs = 2;

  ctx.view.update(ctx.eRHO_K->all_received(), ctx.pi_eRHO_K->all_received(), ctx.eRHO_X->all_received(),
                  ctx.pi_eRHO_X->all_received(), ctx.F_eRHO_K->all_received(), ctx.pi_F_eRHO_K->all_received(),
                  ctx.F_eRHO_X->all_received(), ctx.pi_F_eRHO_X->all_received());
  ctx.h = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(ctx.job, ctx.view.final());

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (rv = ctx.pi_F_eRHO_K->received(j).verify(ctx.E, SUM(ctx.eK_i->all_received()), ctx.eRHO_i->received(j),
                                                 ctx.F_eRHO_K->received(j), ctx.sid, n_elgamal_com_mult_proofs * j + 0))
      return rv;
    if (rv = ctx.pi_F_eRHO_X->received(j).verify(ctx.E, elg_com_t(ctx.curve.generator(), ctx.E + ctx.key->Q),
                                                 ctx.eRHO_i->received(j), ctx.F_eRHO_X->received(j), ctx.sid,
                                                 n_elgamal_com_mult_proofs * j + 1))
      return rv;
    if (rv =
            ctx.pi_eRHO_K->received(j).verify(ctx.E, ctx.eRHO_K->received(j), ctx.sid, n_uc_elgamal_com_proofs * j + 2))
      return rv;
    if (rv =
            ctx.pi_eRHO_X->received(j).verify(ctx.E, ctx.eRHO_X->received(j), ctx.sid, n_uc_elgamal_com_proofs * j + 3))
      return rv;
  }

  ctx.Y_eRHO_K = SUM(ctx.F_eRHO_K->all_received()) - SUM(ctx.eRHO_K->all_received());
  ctx.Y_eRHO_X = SUM(ctx.F_eRHO_X->all_received()) - SUM(ctx.eRHO_X->all_received());
  ctx.r_Z_eRHO_K = bn_t::rand(q);
  ctx.r_Z_eRHO_X = bn_t::rand(q);
  ctx.o_Z_eRHO_K = bn_t::rand(q);
  ctx.o_Z_eRHO_X = bn_t::rand(q);
  ctx.Z_eRHO_K_i = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::rerand(ctx.E, ctx.o_Z_eRHO_K * ctx.Y_eRHO_K).rand(ctx.r_Z_eRHO_K));
  ctx.Z_eRHO_X_i = std::make_unique<job_mp_t::uniform_msg_t<elg_com_t>>(
      ctx.job, elg_com_t::rerand(ctx.E, ctx.o_Z_eRHO_X * ctx.Y_eRHO_X).rand(ctx.r_Z_eRHO_X));
  ctx.pi_Z_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>>(
      ctx.job, zk::uc_elgamal_com_mult_private_scalar_t());
  ctx.pi_Z_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::uc_elgamal_com_mult_private_scalar_t>>(
      ctx.job, zk::uc_elgamal_com_mult_private_scalar_t());
  ctx.pi_Z_eRHO_K->prove(ctx.E, ctx.Y_eRHO_K, ctx.Z_eRHO_K_i->msg, ctx.r_Z_eRHO_K, ctx.o_Z_eRHO_K, ctx.sid,
                         n_elgamal_mult_private_scalar_proofs * i + 0);
  ctx.pi_Z_eRHO_X->prove(ctx.E, ctx.Y_eRHO_X, ctx.Z_eRHO_X_i->msg, ctx.r_Z_eRHO_X, ctx.o_Z_eRHO_X, ctx.sid,
                         n_elgamal_mult_private_scalar_proofs * i + 1);

  if (rv = job.plain_broadcast(*ctx.h, *ctx.Z_eRHO_K_i, *ctx.pi_Z_eRHO_K, *ctx.Z_eRHO_X_i, *ctx.pi_Z_eRHO_X)) return rv;
  return SUCCESS;
}

// Step 8: 7th round — verify h, pi_Z, h2, Z, W_*, pi_W, K_i, pi_K, broadcast.
error_t sign_step_8(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i;
  const int n_dh_proofs = 2;
  const int n_elgamal_com_pub_share_equ_proofs = 3;
  const int n_elgamal_mult_private_scalar_proofs = 2;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (ctx.h->msg != ctx.h->received(j)) return coinbase::error(E_CRYPTO);
    if (rv = ctx.pi_Z_eRHO_K->received(j).verify(ctx.E, ctx.Y_eRHO_K, ctx.Z_eRHO_K_i->received(j), ctx.sid,
                                                 n_elgamal_mult_private_scalar_proofs * j + 0))
      return rv;
    if (rv = ctx.pi_Z_eRHO_X->received(j).verify(ctx.E, ctx.Y_eRHO_X, ctx.Z_eRHO_X_i->received(j), ctx.sid,
                                                 n_elgamal_mult_private_scalar_proofs * j + 1))
      return rv;
  }

  ctx.h2 = std::make_unique<job_mp_t::uniform_msg_t<buf256_t>>(
      ctx.job, crypto::sha256_t::hash(ctx.Z_eRHO_K_i->all_received(), ctx.pi_Z_eRHO_K->all_received(),
                                      ctx.Z_eRHO_X_i->all_received(), ctx.pi_Z_eRHO_X->all_received(), ctx.h->msg));
  ctx.Z_eRHO_K = SUM(ctx.Z_eRHO_K_i->all_received());
  ctx.Z_eRHO_X = SUM(ctx.Z_eRHO_X_i->all_received());

  ctx.W_eRHO_K_i = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(ctx.job, ctx.s_i_val * ctx.Z_eRHO_K.L);
  ctx.W_eRHO_X_i = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(ctx.job, ctx.s_i_val * ctx.Z_eRHO_X.L);
  ctx.pi_W_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::dh_t>>(ctx.job, zk::dh_t());
  ctx.pi_W_eRHO_X = std::make_unique<job_mp_t::uniform_msg_t<zk::dh_t>>(ctx.job, zk::dh_t());
  ctx.pi_W_eRHO_K->prove(ctx.Z_eRHO_K.L, ctx.E_i[i], ctx.W_eRHO_K_i->msg, ctx.s_i_val, ctx.sid, n_dh_proofs * i + 0);
  ctx.pi_W_eRHO_X->prove(ctx.Z_eRHO_X.L, ctx.E_i[i], ctx.W_eRHO_X_i->msg, ctx.s_i_val, ctx.sid, n_dh_proofs * i + 1);
  ctx.K_i = std::make_unique<job_mp_t::uniform_msg_t<ecc_point_t>>(ctx.job, ctx.k_i * ctx.curve.generator());
  ctx.pi_K = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>>(
      ctx.job, zk::elgamal_com_pub_share_equ_t());
  ctx.pi_K->prove(ctx.E, ctx.K_i->msg, ctx.eK_i->msg, ctx.r_eK_i, ctx.sid, n_elgamal_com_pub_share_equ_proofs * i + 0);

  if (rv = job.plain_broadcast(*ctx.W_eRHO_K_i, *ctx.pi_W_eRHO_K, *ctx.W_eRHO_X_i, *ctx.pi_W_eRHO_X, *ctx.K_i,
                               *ctx.pi_K, *ctx.h2))
    return rv;
  return SUCCESS;
}

// Step 9: 8th round — verify h2, pi_W, pi_K, K, r, W check, m, beta, eB, pi_R_*, rho_k, send_message_all_to_one.
error_t sign_step_9(job_mp_t& job, sign_ctx_t& ctx) {
  error_t rv;
  int n = ctx.n, i = ctx.i;
  key_t& key = *ctx.key;
  const mod_t& q = ctx.curve.order();
  const int n_elgamal_com_pub_share_equ_proofs = 3;
  const int n_dh_proofs = 2;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    if (ctx.h2->msg != ctx.h2->received(j)) return coinbase::error(E_CRYPTO);
    if (rv = ctx.pi_W_eRHO_K->received(j).verify(ctx.Z_eRHO_K.L, ctx.E_i[j], ctx.W_eRHO_K_i->received(j), ctx.sid,
                                                 n_dh_proofs * j + 0))
      return rv;
    if (rv = ctx.pi_W_eRHO_X->received(j).verify(ctx.Z_eRHO_X.L, ctx.E_i[j], ctx.W_eRHO_X_i->received(j), ctx.sid,
                                                 n_dh_proofs * j + 1))
      return rv;
    if (rv = ctx.pi_K->received(j).verify(ctx.E, ctx.K_i->received(j), ctx.eK_i->received(j), ctx.sid,
                                          n_elgamal_com_pub_share_equ_proofs * j + 0))
      return rv;
  }

  ctx.K = SUM(ctx.K_i->all_received());
  bn_t r_tag = ctx.K.get_x();
  ctx.r = r_tag % q;
  ecc_point_t W_eRHO_K = SUM(ctx.W_eRHO_K_i->all_received());
  ecc_point_t W_eRHO_X = SUM(ctx.W_eRHO_X_i->all_received());
  if (W_eRHO_K != ctx.Z_eRHO_K.R) return coinbase::error(E_CRYPTO);
  if (W_eRHO_X != ctx.Z_eRHO_X.R) return coinbase::error(E_CRYPTO);

  ctx.m = curve_msg_to_bn(ctx.msg, ctx.curve);
  ctx.beta = std::make_unique<job_mp_t::uniform_msg_t<bn_t>>(ctx.job, bn_t());
  MODULO(q) {
    ctx.r_rho_x = ctx.r * ctx.rho_x_i;
    ctx.rho_m = ctx.m * ctx.rho_i;
    ctx.beta->msg = ctx.r_rho_x + ctx.rho_m;
    ctx.r_eR_RHO_X = ctx.r * ctx.r_eRHO_X;
    ctx.r_eR_RHO_M = ctx.m * ctx.r_eRHO_i;
    ctx.r_eB = ctx.r_eR_RHO_X + ctx.r_eR_RHO_M;
  }
  ctx.eB.resize(n);
  for (int j = 0; j < n; j++) {
    elg_com_t eR_RHO_X = ctx.r * ctx.eRHO_X->received(j);
    elg_com_t eRHO_M = ctx.m * ctx.eRHO_i->received(j);
    ctx.eB[j] = eR_RHO_X + eRHO_M;
  }
  ctx.r_eRHO_K_val = ctx.r_eRHO_K;
  ctx.pi_R_eRHO_K = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>>(
      ctx.job, zk::elgamal_com_pub_share_equ_t());
  ctx.pi_R_eB = std::make_unique<job_mp_t::uniform_msg_t<zk::elgamal_com_pub_share_equ_t>>(
      ctx.job, zk::elgamal_com_pub_share_equ_t());
  ecc_point_t RHO_K = ctx.rho_k_i * ctx.curve.generator();
  ecc_point_t B = ctx.beta->msg * ctx.curve.generator();
  ctx.pi_R_eRHO_K->prove(ctx.E, RHO_K, ctx.eRHO_K->msg, ctx.r_eRHO_K_val, ctx.sid,
                         n_elgamal_com_pub_share_equ_proofs * i + 1);
  ctx.pi_R_eB->prove(ctx.E, B, ctx.eB[i], ctx.r_eB, ctx.sid, n_elgamal_com_pub_share_equ_proofs * i + 2);
  ctx.rho_k = std::make_unique<job_mp_t::uniform_msg_t<bn_t>>(ctx.job, ctx.rho_k_i);

  if (rv = job.send_message_all_to_one(ctx.sig_receiver, *ctx.rho_k, *ctx.pi_R_eRHO_K, *ctx.beta, *ctx.pi_R_eB))
    return rv;
  return SUCCESS;
}

// Step 10: Output — sig_receiver verifies and computes sig.
error_t sign_step_10(job_mp_t& job, sign_ctx_t& ctx, buf_t& sig) {
  error_t rv;
  int n = ctx.n, i = ctx.i;
  key_t& key = *ctx.key;
  const mod_t& q = ctx.curve.order();
  const int n_elgamal_com_pub_share_equ_proofs = 3;

  if (!job.is_party_idx(ctx.sig_receiver)) return SUCCESS;

  for (int j = 0; j < n; j++) {
    if (i == j) continue;
    ecc_point_t RHO_K = ctx.rho_k->received(j) * ctx.curve.generator();
    ecc_point_t B = ctx.beta->received(j) * ctx.curve.generator();
    if (rv = ctx.pi_R_eRHO_K->received(j).verify(ctx.E, RHO_K, ctx.eRHO_K->received(j), ctx.sid,
                                                 n_elgamal_com_pub_share_equ_proofs * j + 1))
      return rv;
    if (rv = ctx.pi_R_eB->received(j).verify(ctx.E, B, ctx.eB[j], ctx.sid, n_elgamal_com_pub_share_equ_proofs * j + 2))
      return rv;
  }

  bn_t sum_rho_k = SUM(ctx.rho_k->all_received(), q);
  bn_t sum_beta = SUM(ctx.beta->all_received(), q);
  bn_t s;
  MODULO(q) s = sum_beta / sum_rho_k;
  bn_t s_reduced = q - s;
  if (s_reduced < s) s = s_reduced;
  sig = crypto::ecdsa_signature_t(ctx.curve, ctx.r, s).to_der();
  crypto::ecc_pub_key_t pub(key.Q);
  if (rv = pub.verify(ctx.msg, sig)) return rv;
  return SUCCESS;
}

error_t sign(job_mp_t& job, key_t& key, mem_t msg, const party_idx_t sig_receiver,
             const std::vector<std::vector<int>>& ot_role_map, buf_t& sig) {
  sign_ctx_t ctx;
  error_t rv;
  if (rv = sign_validate_and_begin(job, key, msg, sig_receiver, ot_role_map, ctx)) return rv;
  if (rv = sign_step_1(job, ctx)) return rv;
  if (rv = sign_step_2(job, ctx)) return rv;
  if (rv = sign_step_3(job, ctx)) return rv;
  if (rv = sign_step_4(job, ctx)) return rv;
  if (rv = sign_step_5(job, ctx)) return rv;
  if (rv = sign_step_6(job, ctx)) return rv;
  if (rv = sign_step_7(job, ctx)) return rv;
  if (rv = sign_step_8(job, ctx)) return rv;
  if (rv = sign_step_9(job, ctx)) return rv;
  if (rv = sign_step_10(job, ctx, sig)) return rv;
  return SUCCESS;
}

error_t sign(job_mp_t& job, key_t& key, mem_t msg, const party_idx_t sig_receiver, buf_t& sig) {
  int n = job.get_n_parties();
  std::vector<std::vector<int>> ot_role_map(n, std::vector<int>(n));
  for (int i = 0; i < n; i++) ot_role_map[i][i] = ot_no_role;
  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      ot_role_map[i][j] = ot_sender;
      ot_role_map[j][i] = ot_receiver;
    }
  }
  return sign(job, key, msg, sig_receiver, ot_role_map, sig);
}

}  // namespace coinbase::mpc::ecdsampc
