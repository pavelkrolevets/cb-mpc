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

// Fixed expected receiver output (chosen message per index) for OT_Base.PVW_FixedParams.
// Derived from fixed inputs: choice=0xa5 -> choice[0]=1,choice[1]=0,choice[2]=1,choice[3]=0,choice[4]=0,choice[5]=1,choice[6]=0,choice[7]=1.
// expected[j] = choice[j] ? x1[j] : x0[j] with x0[j] first byte j, x1[j] first byte j+0x10.
static const char* kPVW_FixedParams_expected_hex[] = {
    "10000000000000000000000000000000",  // j=0 choice[0]=1 -> x1[0]
    "01000000000000000000000000000000",  // j=1 choice[1]=0 -> x0[1]
    "12000000000000000000000000000000",  // j=2 choice[2]=1 -> x1[2]
    "03000000000000000000000000000000",  // j=3 choice[3]=0 -> x0[3]
    "04000000000000000000000000000000",  // j=4 choice[4]=0 -> x0[4]
    "15000000000000000000000000000000",  // j=5 choice[5]=1 -> x1[5]
    "06000000000000000000000000000000",  // j=6 choice[6]=0 -> x0[6]
    "17000000000000000000000000000000",  // j=7 choice[7]=1 -> x1[7]
};

// Fixed parameters and expected values: Base OT (PVW) with u=8.
// Compare receiver output against fixed expected hex (chosen message per index).
TEST(OT_Base, PVW_FixedParams) {
  const int u = 8;
  base_ot_protocol_pvw_ctx_t ot;

  ot.sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  bits_t choice = bits_t::from_bin(buf_from_hex("a5"));

  std::vector<buf_t> x0(u), x1(u);
  for (int j = 0; j < u; ++j) {
    char x0_hex[33], x1_hex[33];
    snprintf(x0_hex, sizeof(x0_hex), "%02x000000000000000000000000000000", j);
    snprintf(x1_hex, sizeof(x1_hex), "%02x000000000000000000000000000000", j + 0x10);
    x0[j] = buf_from_hex(x0_hex);
    x1[j] = buf_from_hex(x1_hex);
  }

  EXPECT_OK(ot.step1_R2S(choice));
  EXPECT_OK(ot.step2_S2R(x0, x1));

  std::vector<buf_t> x_out;
  EXPECT_OK(ot.output_R(x_out));

  ASSERT_EQ(static_cast<int>(x_out.size()), u);
  for (int j = 0; j < u; ++j) {
    buf_t expected = buf_from_hex(kPVW_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_out[j], expected) << "index j=" << j << " expected_hex=" << kPVW_FixedParams_expected_hex[j];
  }
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

// Fixed expected receiver output (chosen message per index) for OT_Extension.Main_FixedParams.
// Derived from fixed inputs: r=0x0b (4 bits 1011) -> r[0]=1,r[1]=1,r[2]=0,r[3]=1.
// expected[j] = r[j] ? x1[j] : x0[j] with x0[j] first byte j, x1[j] first byte j+0x20.
static const char* kOT_Extension_Main_FixedParams_expected_hex[] = {
    "20000000000000000000000000000000",  // j=0 r[0]=1 -> x1[0]
    "21000000000000000000000000000000",  // j=1 r[1]=1 -> x1[1]
    "02000000000000000000000000000000",  // j=2 r[2]=0 -> x0[2]
    "23000000000000000000000000000000",  // j=3 r[3]=1 -> x1[3]
};

// Fixed parameters and expected values: OT Extension with u=256 (protocol constant), m=4.
// Compare receiver output against fixed expected hex (chosen message per index).
TEST(OT_Extension, Main_FixedParams) {
  const int u = ot_ext_protocol_ctx_t::u;  // 256
  const int m = 4;
  ot_ext_protocol_ctx_t ot;

  buf_t sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");

  std::vector<buf_t> sigma0(u), sigma1(u), sigma(u);
  for (int j = 0; j < u; ++j) {
    char h0[33], h1[33];
    snprintf(h0, sizeof(h0), "%02x000000000000000000000000000000", j % 256);
    snprintf(h1, sizeof(h1), "%02x000000000000000000000000000000", (j + 0x80) % 256);
    sigma0[j] = buf_from_hex(h0);
    sigma1[j] = buf_from_hex(h1);
  }
  buf_t s_bin = buf_from_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  bits_t s = bits_t::from_bin(s_bin);
  for (int j = 0; j < u; ++j) sigma[j] = s[j] ? sigma1[j] : sigma0[j];

  bits_t r = bits_t::from_bin(buf_from_hex("0b"));
  std::vector<buf_t> x0(m), x1(m);
  for (int j = 0; j < m; ++j) {
    char h0[33], h1[33];
    snprintf(h0, sizeof(h0), "%02x000000000000000000000000000000", j);
    snprintf(h1, sizeof(h1), "%02x000000000000000000000000000000", j + 0x20);
    x0[j] = buf_from_hex(h0);
    x1[j] = buf_from_hex(h1);
  }

  int l = 16 * 8;
  std::vector<buf_t> x_bin;
  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, r, l));
  EXPECT_OK(ot.step2_S2R(sid, s, sigma, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Extension_Main_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j << " expected_hex=" << kOT_Extension_Main_FixedParams_expected_hex[j];
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

// Fixed parameters: OT Extension SenderOneInputRandom with m=4. Compare output to computed expected (x0,x1 from protocol).
TEST(OT_Extension, SenderOneInputRandom_FixedParams) {
  const int u = ot_ext_protocol_ctx_t::u;
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_t ot;

  buf_t sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  std::vector<buf_t> sigma0(u), sigma1(u), sigma(u);
  for (int j = 0; j < u; ++j) {
    char h0[33], h1[33];
    snprintf(h0, sizeof(h0), "%02x000000000000000000000000000000", j % 256);
    snprintf(h1, sizeof(h1), "%02x000000000000000000000000000000", (j + 0x80) % 256);
    sigma0[j] = buf_from_hex(h0);
    sigma1[j] = buf_from_hex(h1);
  }
  bits_t s = bits_t::from_bin(buf_from_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  for (int j = 0; j < u; ++j) sigma[j] = s[j] ? sigma1[j] : sigma0[j];

  std::vector<bn_t> delta(m);
  delta[0] = bn_t::from_hex("1");
  delta[1] = bn_t::from_hex("2");
  delta[2] = bn_t::from_hex("3");
  delta[3] = bn_t::from_hex("4");

  bits_t recv_choice = bits_t::from_bin(buf_from_hex("0b"));
  int bitlen = q.get_bits_count();

  std::vector<bn_t> x0, x1;
  std::vector<buf_t> x_bin;
  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, recv_choice, bitlen));
  EXPECT_OK(ot.step2_S2R_sender_one_input_random(sid, s, sigma, delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    bn_t expected = recv_choice[j] ? x1[j] : x0[j];
    EXPECT_EQ(bn_t::from_bin(x_bin[j]), expected) << "index j=" << j;
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q) << "index j=" << j << " x1=x0+delta";
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

// Fixed parameters: OT Extension SenderRandom. r=0x0b gives m=8 (1 byte). Compare r[j]?x1_bin:x0_bin to receiver output x.
TEST(OT_Extension, SenderRandom_FixedParams) {
  const int u = ot_ext_protocol_ctx_t::u;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_t ot;

  buf_t sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  std::vector<buf_t> sigma0(u), sigma1(u), sigma(u);
  for (int j = 0; j < u; ++j) {
    char h0[33], h1[33];
    snprintf(h0, sizeof(h0), "%02x000000000000000000000000000000", j % 256);
    snprintf(h1, sizeof(h1), "%02x000000000000000000000000000000", (j + 0x80) % 256);
    sigma0[j] = buf_from_hex(h0);
    sigma1[j] = buf_from_hex(h1);
  }
  bits_t s = bits_t::from_bin(buf_from_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  for (int j = 0; j < u; ++j) sigma[j] = s[j] ? sigma1[j] : sigma0[j];

  bits_t recv_choice = bits_t::from_bin(buf_from_hex("0b"));  // 8 bits -> m=8
  int bitlen = q.get_bits_count();
  const int m = recv_choice.count();

  std::vector<buf_t> x;
  std::vector<buf_t> x0_bin, x1_bin;
  EXPECT_OK(ot.sender_random_step1_R2S(sid, sigma0, sigma1, recv_choice, bitlen, x));
  EXPECT_OK(ot.sender_random_output_S(sid, s, sigma, m, bitlen, x0_bin, x1_bin));

  ASSERT_EQ(static_cast<int>(x.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = recv_choice[j] ? x1_bin[j] : x0_bin[j];
    EXPECT_EQ(x[j], expected) << "index j=" << j;
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

// Fixed expected receiver output for OT.FullOT2P_FixedParams (from log output).
// r=0x0b: expected[j] = r[j] ? x1[j] : x0[j] with x0=(1,2,3,4), x1=(11,12,13,14). 32-byte big-endian hex.
static const char* kFullOT2P_FixedParams_expected_hex[] = {
    "0000000000000000000000000000000000000000000000000000000000000011",  // j=0 r[0]=1 -> x1[0]=11
    "0000000000000000000000000000000000000000000000000000000000000012",  // j=1 r[1]=1 -> x1[1]=12
    "0000000000000000000000000000000000000000000000000000000000000003",  // j=2 r[2]=0 -> x0[2]=3
    "0000000000000000000000000000000000000000000000000000000000000014",  // j=3 r[3]=1 -> x1[3]=14
};

// Fixed parameters and expected values: Full OT 2-party with m=4. Compare receiver output to fixed expected hex (from log).
TEST(OT, FullOT2P_FixedParams) {
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  int l = q.get_bits_count();
  bits_t r = bits_t::from_bin(buf_from_hex("0b"));

  std::vector<bn_t> x0(m), x1(m);
  x0[0] = bn_t::from_hex("1");
  x0[1] = bn_t::from_hex("2");
  x0[2] = bn_t::from_hex("3");
  x0[3] = bn_t::from_hex("4");
  x1[0] = bn_t::from_hex("11");
  x1[1] = bn_t::from_hex("12");
  x1[2] = bn_t::from_hex("13");
  x1[3] = bn_t::from_hex("14");

  std::vector<buf_t> x_bin;
  ot_protocol_pvw_ctx_t ot(curve);
  ot.base.sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(x0, x1, l));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kFullOT2P_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j << " expected_hex=" << kFullOT2P_FixedParams_expected_hex[j];
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

// Fixed parameters: Sender-One-Input-Random OT 2-party with m=4. Compare output to computed expected (x0,x1 from protocol).
TEST(OT, SenderOneInputRandomOT2P_FixedParams) {
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  int l = q.get_bits_count();
  bits_t r = bits_t::from_bin(buf_from_hex("0b"));

  std::vector<bn_t> delta(m);
  delta[0] = bn_t::from_hex("1");
  delta[1] = bn_t::from_hex("2");
  delta[2] = bn_t::from_hex("3");
  delta[3] = bn_t::from_hex("4");

  std::vector<bn_t> x0, x1;
  std::vector<buf_t> x_bin;
  ot_protocol_pvw_ctx_t ot(curve);
  ot.base.sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    bn_t expected = r[j] ? x1[j] : x0[j];
    EXPECT_EQ(bn_t::from_bin(x_bin[j]), expected) << "index j=" << j;
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q) << "index j=" << j << " x1=x0+delta";
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