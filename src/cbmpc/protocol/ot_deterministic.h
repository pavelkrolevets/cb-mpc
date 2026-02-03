#pragma once
// Deterministic OT: same API as ot.h but all randomness replaced by RO-derived values.
// For use in deterministic tests (e.g. ecdsa_mp_steps fixed-parameter tests).
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/ro.h>
#include <cbmpc/zk/zk_ec.h>
#include <cbmpc/zk/zk_pedersen.h>

#include "ot.h"

namespace coinbase::mpc {

/** Deterministic base OT (PVW): r[i], s0,t0,s1,t1 derived from sid via RO. */
struct base_ot_protocol_pvw_ctx_det_t {
  enum { l = 128 };

  base_ot_protocol_pvw_ctx_det_t(ecurve_t curve = crypto::curve_p256) : curve(curve) {}

  std::vector<buf_t> x0, x1;
  coinbase::bits_t b;
  int m = 0;
  buf_t sid;
  const ecurve_t curve;

  std::vector<bn_t> r;
  std::vector<ecc_point_t> A, B;
  std::vector<ecc_point_t> U0, U1;
  std::vector<buf_t> V0, V1;

  auto msg1() { return std::tie(A, B); }
  auto msg2() { return std::tie(U0, V0, U1, V1); }

  using msg1_t = std::tuple<std::vector<ecc_point_t>&, std::vector<ecc_point_t>&>;
  using msg2_t =
      std::tuple<std::vector<ecc_point_t>&, std::vector<buf_t>&, std::vector<ecc_point_t>&, std::vector<buf_t>&>;

  error_t step1_R2S(const coinbase::bits_t& b);
  error_t step2_S2R(const std::vector<buf_t>& x0, const std::vector<buf_t>& x1);
  error_t output_R(std::vector<buf_t>& x);
};

/** Deterministic OT extension: r = rr + RO(sid) instead of random. */
struct ot_ext_protocol_ctx_det_t {
  static const int u = 256;
  static const int d = 3;
  static const int kappa = 128;

  std::vector<buf_t> x0, x1;
  coinbase::bits_t b;
  int l = 0;
  buf_t sid;

  v_matrix_256cols_t T;
  coinbase::bits_t r;

  h_matrix_256rows_t U;
  std::vector<buf128_t> v0, v1;
  std::vector<buf_t> w0, w1;

  auto msg1() { return std::tie(U, v0, v1); }
  auto msg2() { return std::tie(w0, w1); }
  auto msg2_delta() { return std::tie(w1); }

  using msg1_t = std::tuple<h_matrix_256rows_t&, std::vector<buf128_t>&, std::vector<buf128_t>&>;
  using msg2_t = std::tuple<std::vector<buf_t>&, std::vector<buf_t>&>;
  using msg2_delta_t = std::tuple<std::vector<buf_t>&>;

  error_t step1_R2S(mem_t sid, const std::vector<buf_t>& sigma0, const std::vector<buf_t>& sigma1,
                    const coinbase::bits_t& rr, int l);
  error_t step2_S2R(mem_t sid, const coinbase::bits_t& s, const std::vector<buf_t>& sigma, const std::vector<buf_t>& x0,
                    const std::vector<buf_t>& x1);
  error_t step2_S2R_sender_one_input_random(mem_t sid, const coinbase::bits_t& s, const std::vector<buf_t>& sigma,
                                            const std::vector<bn_t>& delta, const mod_t& q, std::vector<bn_t>& x0_out,
                                            std::vector<bn_t>& x1_out);
  error_t step2_S2R_helper(mem_t sid, const coinbase::bits_t& s, const std::vector<buf_t>& sigma,
                           const bool sender_one_input_random_mode, const std::vector<buf_t>& x0,
                           const std::vector<buf_t>& x1, const std::vector<bn_t>& delta, const mod_t& q,
                           std::vector<bn_t>& x0_out, std::vector<bn_t>& x1_out);
  error_t output_R(int m, std::vector<buf_t>& x);
};

/** Full deterministic OT (base + extension) for ECDSA-MP step-wise sign. */
struct ot_protocol_pvw_ctx_det_t {
  static const int u = ot_ext_protocol_ctx_det_t::u;
  base_ot_protocol_pvw_ctx_det_t base;
  ot_ext_protocol_ctx_det_t ext;

  ot_protocol_pvw_ctx_det_t(ecurve_t curve = crypto::curve_p256) : base(curve) {}

  auto msg1() { return base.msg1(); }
  auto msg2() { return std::tuple_cat(base.msg2(), ext.msg1()); }
  auto msg3() { return ext.msg2(); }
  auto msg3_delta() { return ext.msg2_delta(); }

  using msg1_t = base_ot_protocol_pvw_ctx_det_t::msg1_t;
  using msg2_t = std::tuple<std::vector<ecc_point_t>&, std::vector<buf_t>&, std::vector<ecc_point_t>&,
                            std::vector<buf_t>&, h_matrix_256rows_t&, std::vector<buf128_t>&, std::vector<buf128_t>&>;
  using msg3_t = ot_ext_protocol_ctx_det_t::msg2_t;
  using msg3_delta_t = ot_ext_protocol_ctx_det_t::msg2_delta_t;

  error_t step1_S2R();
  error_t step2_R2S(const coinbase::bits_t& r, int l);
  error_t step3_S2R(const std::vector<buf_t>& x0, const std::vector<buf_t>& x1);
  error_t step3_S2R(const std::vector<bn_t>& x0, const std::vector<bn_t>& x1, int l);
  error_t step3_S2R(const std::vector<bn_t>& delta, const mod_t& q, std::vector<bn_t>& x0, std::vector<bn_t>& x1);
  error_t output_R(int m, std::vector<buf_t>& x);
  error_t output_R(int m, std::vector<bn_t>& x);
};

}  // namespace coinbase::mpc
