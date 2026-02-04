#include <gtest/gtest.h>

#include <cbmpc/core/strext.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/ro.h>
#include <cbmpc/protocol/ot.h>

#include "utils/test_macros.h"

using namespace coinbase;
using namespace coinbase::mpc;

namespace {

static buf_t buf_from_hex(const char* hex) {
  buf_t out;
  strext::from_hex(out, std::string(hex));
  return out;
}

TEST(OT_Base, PVW) {
  const int u = 256;
  base_ot_protocol_pvw_ctx_t ot;
  bits_t b = crypto::gen_random_bits(u);
  std::vector<buf_t> x0, x1, x_out;
  x0.resize(u);
  x1.resize(u);
  for (int j = 0; j < u; ++j) {
    x0[j] = crypto::gen_random(16);
    x1[j] = crypto::gen_random(16);
  }
  ot.sid = crypto::gen_random(16);
  EXPECT_OK(ot.step1_R2S(b));
  EXPECT_OK(ot.step2_S2R(x0, x1));
  EXPECT_OK(ot.output_R(x_out));
  for (int j = 0; j < u; ++j) {
    buf_t x_truth = b[j] ? x1[j] : x0[j];
    EXPECT_EQ(x_truth, x_out[j]);
  }
}

TEST(OT_Extension, Step1_R2S_Success) {
  const int u = ot_ext_protocol_ctx_t::u;
  const int d = ot_ext_protocol_ctx_t::d;
  const int kappa = ot_ext_protocol_ctx_t::kappa;

  buf_t sid = buf_from_hex("00000000000000000000000000000001");
  buf_t sigma0_fixed = buf_from_hex("000102030405060708090a0b0c0d0e0f");
  buf_t sigma1_fixed = buf_from_hex("f0e0d0c0b0a090807060504030201000");
  buf_t rr_bin = buf_from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
  bits_t rr = bits_t::from_bin(rr_bin);

  std::vector<buf_t> sigma0(u, sigma0_fixed), sigma1(u, sigma1_fixed);

  // Fixed extra bits (kappa+pad = 128 when m=256) for deterministic output
  buf_t fixed_extra_bin = buf_from_hex("2122232425262728292a2b2c2d2e2f30");
  bits_t fixed_r_extra = bits_t::from_bin(fixed_extra_bin);

  ot_ext_protocol_ctx_t ot;
  int m = 256;
  int l = 128;

  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, rr, l, &fixed_r_extra));

  // l is rounded up to multiple of 8
  EXPECT_EQ(ot.l, 128);
  // r = rr + fixed_r_extra; m=256 so pad=0, so r.count() == m + kappa
  EXPECT_EQ(ot.r.count(), m + kappa);
  auto [U_ref, v0_ref, v1_ref] = ot.msg1();
  EXPECT_EQ(U_ref.rows(), 256);
  EXPECT_EQ(U_ref.cols(), m + kappa);
  EXPECT_EQ(static_cast<int>(v0_ref.size()), u * d);
  EXPECT_EQ(static_cast<int>(v1_ref.size()), u * d);

  // Fixed expected results: compare hash of each of U, v0, v1 (deterministic with fixed inputs)
  buf256_t hash_U = crypto::sha256_t::hash(U_ref.bin());
  buf_t v0_cat;
  for (const auto& b : v0_ref) v0_cat += mem_t(b);
  buf256_t hash_v0 = crypto::sha256_t::hash(v0_cat);
  buf_t v1_cat;
  for (const auto& b : v1_ref) v1_cat += mem_t(b);
  buf256_t hash_v1 = crypto::sha256_t::hash(v1_cat);

  EXPECT_EQ(strext::to_hex(mem_t(hash_U)), "d5d8626a28b23eed7e52db160c420fe48bab09f9f37ea4a5d067f35157ad4a66");
  EXPECT_EQ(strext::to_hex(mem_t(hash_v0)), "2c2ce311c4e7de6d74e3e82e2ec85e2e268378d90fc702a89e12b63dc5d04fe9");
  EXPECT_EQ(strext::to_hex(mem_t(hash_v1)), "0ebd5cd6986bb0a3eef0c367851ca944435d3fbfe81c068b6e6c9a8981139a8a");
}

// Validates ot_ext_protocol_ctx_t::step2_S2R (OTExtension-2-StoR-1P): receiver ran step1_R2S,
// sender runs step2_S2R(sid, s, sigma, x0, x1); receiver output must match (rr[j] ? x1[j] : x0[j]).
TEST(OT_Extension, Step2_S2R_Success) {
  const int u = ot_ext_protocol_ctx_t::u;
  buf_t sid = buf_from_hex("00000000000000000000000000000001");
  buf_t sigma0_fixed = buf_from_hex("000102030405060708090a0b0c0d0e0f");
  buf_t sigma1_fixed = buf_from_hex("f0e0d0c0b0a090807060504030201000");
  buf_t rr_bin = buf_from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
  bits_t rr = bits_t::from_bin(rr_bin);
  buf_t fixed_extra_bin = buf_from_hex("2122232425262728292a2b2c2d2e2f30");
  bits_t fixed_r_extra = bits_t::from_bin(fixed_extra_bin);

  std::vector<buf_t> sigma0(u, sigma0_fixed), sigma1(u, sigma1_fixed);
  bits_t s = bits_t::from_bin(buf_from_hex("0000000000000000000000000000000000000000000000000000000000000001"));
  std::vector<buf_t> sigma(u);
  for (int j = 0; j < u; ++j) sigma[j] = s[j] ? sigma1[j] : sigma0[j];

  int m = 256;
  int l = 128;
  std::vector<buf_t> x0(m), x1(m);
  for (int j = 0; j < m; ++j) {
    x0[j] = buf_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    x1[j] = buf_from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  }

  ot_ext_protocol_ctx_t ot;
  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, rr, l, &fixed_r_extra));
  EXPECT_OK(ot.step2_S2R(sid, s, sigma, x0, x1));

  std::vector<buf_t> x_bin;
  EXPECT_OK(ot.output_R(m, x_bin));
  for (int j = 0; j < m; ++j) {
    buf_t expected = rr[j] ? x1[j] : x0[j];
    EXPECT_EQ(x_bin[j], expected);
  }
}

TEST(OT_Extension, Main) {
  const int u = 256;
  const int m = 1 << 16;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_t ot;
  bits_t s = crypto::gen_random_bits(u);
  std::vector<buf_t> sigma0, sigma1, sigma, x_out;
  sigma0.resize(u);
  sigma1.resize(u);
  sigma.resize(u);
  for (int j = 0; j < u; ++j) {
    sigma0[j] = crypto::gen_random(16);
    sigma1[j] = crypto::gen_random(16);
  }
  for (int j = 0; j < u; ++j) {
    sigma[j] = s[j] ? sigma1[j] : sigma0[j];
  }
  std::vector<buf_t> x0, x1;
  x0.resize(m);
  x1.resize(m);
  for (int j = 0; j < m; ++j) {
    x0[j] = crypto::gen_random(16);
    x1[j] = crypto::gen_random(16);
  }
  // Start of OT Extension
  std::vector<buf_t> x_bin;
  buf_t sid = crypto::gen_random(16);
  bits_t r = crypto::gen_random_bits(m);
  int l = x0[0].size() * 8;
  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, r, l));
  EXPECT_OK(ot.step2_S2R(sid, s, sigma, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  for (int j = 0; j < m; ++j) {
    buf_t x = r[j] ? x1[j] : x0[j];
    EXPECT_EQ(x, x_bin[j]);
  }
}

TEST(OT_Extension, SenderOneInputRandom) {
  const int u = 256;
  const int m = 1 << 16;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_t ot;
  bits_t s = crypto::gen_random_bits(u);
  std::vector<buf_t> sigma0, sigma1, sigma, x_out;
  sigma0.resize(u);
  sigma1.resize(u);
  sigma.resize(u);
  for (int j = 0; j < u; ++j) {
    sigma0[j] = crypto::gen_random(16);
    sigma1[j] = crypto::gen_random(16);
  }
  for (int j = 0; j < u; ++j) {
    sigma[j] = s[j] ? sigma1[j] : sigma0[j];
  }
  std::vector<bn_t> delta(m);
  for (int j = 0; j < m; ++j) delta[j] = bn_t::rand(q);
  // Start of OT Extension
  std::vector<bn_t> x0, x1;
  std::vector<buf_t> x_bin;
  buf_t sid = crypto::gen_random(16);
  bits_t r = crypto::gen_random_bits(m);
  int l = q.get_bits_count();

  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, r, l));
  EXPECT_OK(ot.step2_S2R_sender_one_input_random(sid, s, sigma, delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));
  for (int j = 0; j < m; ++j) {
    bn_t x = r[j] ? x1[j] : x0[j];
    EXPECT_EQ(x, bn_t::from_bin(x_bin[j]));
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q);
  }
}

TEST(OT_Extension, SenderRandom) {
  const int u = 256;
  const int m = 1 << 16;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_t ot;
  bits_t s = crypto::gen_random_bits(u);
  std::vector<buf_t> sigma0, sigma1, sigma, x, x_out;
  sigma0.resize(u);
  sigma1.resize(u);
  sigma.resize(u);
  for (int j = 0; j < u; ++j) {
    sigma0[j] = crypto::gen_random(16);
    sigma1[j] = crypto::gen_random(16);
    x.push_back(crypto::gen_random(16));
  }
  for (int j = 0; j < u; ++j) {
    sigma[j] = s[j] ? sigma1[j] : sigma0[j];
  }
  std::vector<bn_t> delta(m);
  for (int j = 0; j < m; ++j) delta[j] = bn_t::rand(q);
  // Start of OT Extension
  std::vector<buf_t> x0_bin, x1_bin;
  buf_t sid = crypto::gen_random(16);
  bits_t r = crypto::gen_random_bits(m);
  int l = q.get_bits_count();

  EXPECT_OK(ot.sender_random_step1_R2S(sid, sigma0, sigma1, r, l, x));
  EXPECT_OK(ot.sender_random_output_S(sid, s, sigma, m, l, x0_bin, x1_bin));
  for (int j = 0; j < m; ++j) {
    EXPECT_EQ(r[j] ? x1_bin[j] : x0_bin[j], x[j]);
  }
}

TEST(OT, FullOT2P) {
  const int u = 256;
  const int m = 1 << 16;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  int l = q.get_bits_count();
  bits_t r = crypto::gen_random_bits(m);

  std::vector<bn_t> x0, x1;
  x0.resize(m);
  x1.resize(m);
  for (int j = 0; j < m; ++j) {
    x0[j] = bn_t::rand(q);
    x1[j] = bn_t::rand(q);
  }

  // Start of OT
  std::vector<buf_t> x_bin;
  ot_protocol_pvw_ctx_t ot(curve);
  ot.base.sid = crypto::gen_random(16);
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(x0, x1, l));
  EXPECT_OK(ot.output_R(m, x_bin));
  for (int j = 0; j < m; ++j) {
    bn_t x = r[j] ? x1[j] : x0[j];
    EXPECT_EQ(x, bn_t::from_bin(x_bin[j]));
  }
}

TEST(OT, SenderOneInputRandomOT2P) {
  const int u = 256;
  const int m = 1 << 16;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  int l = q.get_bits_count();
  bits_t r = crypto::gen_random_bits(m);

  std::vector<bn_t> x0, x1;
  std::vector<bn_t> delta(m);
  for (int j = 0; j < m; ++j) delta[j] = bn_t::rand(q);

  // Start of OT
  std::vector<buf_t> x_bin;
  ot_protocol_pvw_ctx_t ot(curve);
  ot.base.sid = crypto::gen_random(16);
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));
  for (int j = 0; j < m; ++j) {
    bn_t x = r[j] ? x1[j] : x0[j];
    EXPECT_EQ(x, bn_t::from_bin(x_bin[j]));
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q);
  }
}

}  // namespace