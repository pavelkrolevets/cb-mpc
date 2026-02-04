#include <cstdio>
#include <gtest/gtest.h>
#include <string>

#include <cbmpc/core/strext.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/ro.h>
#include <cbmpc/protocol/ot_deterministic.h>

#include "utils/test_macros.h"

using namespace coinbase;
using namespace coinbase::mpc;

namespace {

static buf_t buf_from_hex(const char* hex) {
  buf_t out;
  strext::from_hex(out, std::string(hex));
  return out;
}

// Fixed seed for deterministic derivation (no random values in tests).
static const buf_t kSeed = buf_from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

static buf_t det_buf(mem_t seed, int index, const std::string& tag, int bits) {
  return crypto::ro::hash_string(seed, index, tag).bitlen(bits);
}

static bits_t det_bits(mem_t seed, const std::string& tag, int bits) {
  return bits_t::from_bin(crypto::ro::hash_string(seed, tag).bitlen(bits));
}

static bn_t det_bn_mod(mem_t seed, int index, const std::string& tag, const mod_t& q) {
  bn_t x = crypto::ro::hash_number(seed, index, tag).mod(q);
  return x == 0 ? bn_t(1) : x;
}

// Fixed expected receiver output for OT_Base_Det.PVW_FixedParams.
// choice=0xa5 -> choice[j] ? x1[j] : x0[j] with x0[j] first byte j, x1[j] first byte j+0x10.
static const char* kOT_Base_Det_PVW_FixedParams_expected_hex[] = {
    "10000000000000000000000000000000",  // j=0 choice[0]=1 -> x1[0]
    "01000000000000000000000000000000",  // j=1 choice[1]=0 -> x0[1]
    "12000000000000000000000000000000",  // j=2 choice[2]=1 -> x1[2]
    "03000000000000000000000000000000",  // j=3 choice[3]=0 -> x0[3]
    "04000000000000000000000000000000",  // j=4 choice[4]=0 -> x0[4]
    "15000000000000000000000000000000",  // j=5 choice[5]=1 -> x1[5]
    "06000000000000000000000000000000",  // j=6 choice[6]=0 -> x0[6]
    "17000000000000000000000000000000",  // j=7 choice[7]=1 -> x1[7]
};

TEST(OT_Base_Det, PVW_FixedParams) {
  const int u = 8;
  base_ot_protocol_pvw_ctx_det_t ot(crypto::curve_secp256k1);

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
    buf_t expected = buf_from_hex(kOT_Base_Det_PVW_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_out[j], expected) << "index j=" << j
                                  << " expected_hex=" << kOT_Base_Det_PVW_FixedParams_expected_hex[j];
  }
}

// Fixed expected receiver output for OT_Base_Det.PVW (kSeed, u=8). Chosen message per index.
static const char* kOT_Base_Det_PVW_expected_hex[] = {
    "13d8a132eeafa6178c94282dd015b684", "f1de7be5d279ef4ae338bba408aa1672", "e91559db196f014b35d1537f63c91640",
    "9f2d7f7080a447a34472191573826992", "e80b2f12b65de3edb139a6f54b24ea92", "86f7e16dc03c49d7c52597c21532d92f",
    "205546c6a01bb1c54421192cacb6c259", "6d393c33e8cfa9e74c831cc7608fdd38",
};

TEST(OT_Base_Det, PVW) {
  const int u = 8;
  base_ot_protocol_pvw_ctx_det_t ot(crypto::curve_secp256k1);
  ot.sid = det_buf(kSeed, 0, "base_sid", 128);
  bits_t b = det_bits(kSeed, "base_b", u);
  std::vector<buf_t> x0(u), x1(u), x_out;
  for (int j = 0; j < u; ++j) {
    x0[j] = det_buf(kSeed, j, "base_x0", 128);
    x1[j] = det_buf(kSeed, j, "base_x1", 128);
  }
  EXPECT_OK(ot.step1_R2S(b));
  EXPECT_OK(ot.step2_S2R(x0, x1));
  EXPECT_OK(ot.output_R(x_out));
  ASSERT_EQ(static_cast<int>(x_out.size()), u);
  for (int j = 0; j < u; ++j) {
    buf_t expected = buf_from_hex(kOT_Base_Det_PVW_expected_hex[j]);
    EXPECT_EQ(x_out[j], expected) << "index j=" << j;
  }
}

// Fixed expected receiver output for OT_Extension_Det.Main_FixedParams.
// r=0x0b -> r[j] ? x1[j] : x0[j] with x0[j] first byte j, x1[j] first byte j+0x20.
static const char* kOT_Extension_Det_Main_FixedParams_expected_hex[] = {
    "20000000000000000000000000000000",  // j=0 r[0]=1 -> x1[0]
    "21000000000000000000000000000000",  // j=1 r[1]=1 -> x1[1]
    "02000000000000000000000000000000",  // j=2 r[2]=0 -> x0[2]
    "23000000000000000000000000000000",  // j=3 r[3]=1 -> x1[3]
};

TEST(OT_Extension_Det, Main_FixedParams) {
  const int u = ot_ext_protocol_ctx_det_t::u;
  const int m = 4;
  ot_ext_protocol_ctx_det_t ot;

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
    buf_t expected = buf_from_hex(kOT_Extension_Det_Main_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j
                                  << " expected_hex=" << kOT_Extension_Det_Main_FixedParams_expected_hex[j];
  }
}

// Fixed expected receiver output for OT_Extension_Det.Main (kSeed, m=4).
static const char* kOT_Extension_Det_Main_expected_hex[] = {
    "3549da3780a8d9e13c07256a12c02ef9",
    "250d587c0555aa88d62995feea1eb5a0",
    "d0d50689dca4e5ba7bb8c73bfd8e258b",
    "fc24de820e4cc8276a086504653300a2",
};

TEST(OT_Extension_Det, Main) {
  const int u = 256;
  const int m = 4;
  ot_ext_protocol_ctx_det_t ot;
  buf_t sid = det_buf(kSeed, 0, "ext_main_sid", 128);
  bits_t s = det_bits(kSeed, "ext_main_s", u);
  std::vector<buf_t> sigma0(u), sigma1(u), sigma(u);
  for (int j = 0; j < u; ++j) {
    sigma0[j] = det_buf(kSeed, j, "ext_main_sigma0", 128);
    sigma1[j] = det_buf(kSeed, j, "ext_main_sigma1", 128);
    sigma[j] = s[j] ? sigma1[j] : sigma0[j];
  }
  bits_t r = det_bits(kSeed, "ext_main_r", m * 8);
  std::vector<buf_t> x0(m), x1(m);
  for (int j = 0; j < m; ++j) {
    x0[j] = det_buf(kSeed, j, "ext_main_x0", 128);
    x1[j] = det_buf(kSeed, j, "ext_main_x1", 128);
  }
  int l = 128;
  std::vector<buf_t> x_bin;
  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, r, l));
  EXPECT_OK(ot.step2_S2R(sid, s, sigma, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Extension_Det_Main_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j;
  }
}

// Fixed expected receiver output for OT_Extension_Det.SenderOneInputRandom_FixedParams.
// Deterministic output from fixed sid, sigma, s, delta, recv_choice=0x0b (r[0]=1,r[1]=1,r[2]=0,r[3]=1).
static const char* kOT_Extension_Det_SenderOneInputRandom_FixedParams_expected_hex[] = {
    "7576a84bb65318dbdefc829aab5d6ce1b896a22d0ff7b8c61f2cdb543e4749ce",
    "41269bdf236187c4b80cc61e05d875f3c9aa526c0de5e52086797d6d5edf02ea",
    "39304f7aac3b759f4291aaade982809a24f3f60cef1dce8ac36d650c9fe8f120",
    "7ca5fbb4093855013f429d465b6aeb2e4dc398a1781f2d8c40de8ddcaf988f7f",
};

TEST(OT_Extension_Det, SenderOneInputRandom_FixedParams) {
  const int u = ot_ext_protocol_ctx_det_t::u;
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_det_t ot;

  buf_t sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  std::vector<buf_t> sigma0(u), sigma1(u), sigma(u);
  for (int j = 0; j < u; ++j) {
    char h0[33], h1[33];
    snprintf(h0, sizeof(h0), "%02x000000000000000000000000000000", j % 256);
    snprintf(h1, sizeof(h1), "%02x000000000000000000000000000000", (j + 0x80) % 256);
    sigma0[j] = buf_from_hex(h0);
    sigma1[j] = buf_from_hex(h1);
  }
  bits_t s =
      bits_t::from_bin(buf_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
    buf_t expected = buf_from_hex(kOT_Extension_Det_SenderOneInputRandom_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j << " expected_hex="
                                  << kOT_Extension_Det_SenderOneInputRandom_FixedParams_expected_hex[j];
  }
  for (int j = 0; j < m; ++j) {
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q) << "index j=" << j << " x1=x0+delta";
  }
}

TEST(OT_Extension_Det, SenderOneInputRandom) {
  const int u = 256;
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  ot_ext_protocol_ctx_det_t ot;
  buf_t sid = det_buf(kSeed, 0, "ext_sor_sid", 128);
  bits_t s = det_bits(kSeed, "ext_sor_s", u);
  std::vector<buf_t> sigma0(u), sigma1(u), sigma(u);
  for (int j = 0; j < u; ++j) {
    sigma0[j] = det_buf(kSeed, j, "ext_sor_sigma0", 128);
    sigma1[j] = det_buf(kSeed, j, "ext_sor_sigma1", 128);
    sigma[j] = s[j] ? sigma1[j] : sigma0[j];
  }
  bits_t r = det_bits(kSeed, "ext_sor_r", m * 8);
  std::vector<bn_t> delta(m);
  for (int j = 0; j < m; ++j) delta[j] = det_bn_mod(kSeed, j, "ext_sor_delta", q);
  std::vector<bn_t> x0, x1;
  std::vector<buf_t> x_bin;
  int l = q.get_bits_count();

  EXPECT_OK(ot.step1_R2S(sid, sigma0, sigma1, r, l));
  EXPECT_OK(ot.step2_S2R_sender_one_input_random(sid, s, sigma, delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  // Fixed expected receiver output for OT_Extension_Det.SenderOneInputRandom (kSeed, m=4).
  static const char* kOT_Extension_Det_SenderOneInputRandom_expected_hex[] = {
      "7924e7ed88c239c75083a97cbaf067f9d7b44a52ee967b21d594024a5f37cc5d",
      "f172208a845d14b8aa121d0f4969842fc76fbfc062217091bdfcfe46815bf03e",
      "604fc2318c58a7dbeaf7060c58e77099a804c6bf11070bfe2915d7eaeede453a",
      "bc33b413cb9ef11f79bfc0396ebef70887b463adeb7f748e06aeee7378871828",
  };
  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Extension_Det_SenderOneInputRandom_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j;
  }
  for (int j = 0; j < m; ++j) {
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q) << "index j=" << j << " x1=x0+delta";
  }
}

// Fixed expected receiver output for OT_Det.FullOT2P_FixedParams.
// r=0x0b: expected[j] = r[j] ? x1[j] : x0[j] with x0=(1,2,3,4), x1=(11,12,13,14). 32-byte big-endian hex.
static const char* kOT_Det_FullOT2P_FixedParams_expected_hex[] = {
    "0000000000000000000000000000000000000000000000000000000000000011",  // j=0 r[0]=1 -> x1[0]=11
    "0000000000000000000000000000000000000000000000000000000000000012",  // j=1 r[1]=1 -> x1[1]=12
    "0000000000000000000000000000000000000000000000000000000000000003",  // j=2 r[2]=0 -> x0[2]=3
    "0000000000000000000000000000000000000000000000000000000000000014",  // j=3 r[3]=1 -> x1[3]=14
};

TEST(OT_Det, FullOT2P_FixedParams) {
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
  ot_protocol_pvw_ctx_det_t ot(curve);
  ot.base.sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(x0, x1, l));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Det_FullOT2P_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j
                                  << " expected_hex=" << kOT_Det_FullOT2P_FixedParams_expected_hex[j];
  }
}

// Fixed expected receiver output for OT_Det.FullOT2P (kSeed, m=4).
static const char* kOT_Det_FullOT2P_expected_hex[] = {
    "edca68ab31456c053391da9a9d1273ca2412a8a6cabc15a22b02fb5d2f7d5e06",
    "b45f40e795c47fa5507236ebab152fc55f29e892e97d895ac9109ba1ba8f4123",
    "1cfa25b354064a50068398b50b9652c27a3964b83e33baf7736fe0b86abe0c63",
    "96bf9308f4c6f299c915022159923b3157f5543c2550e559fa93203d0037ae33",
};

TEST(OT_Det, FullOT2P) {
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  int l = q.get_bits_count();
  ot_protocol_pvw_ctx_det_t ot(curve);
  ot.base.sid = det_buf(kSeed, 0, "full_ot_sid", 128);
  bits_t r = det_bits(kSeed, "full_ot_r", m * 8);
  std::vector<bn_t> x0(m), x1(m);
  for (int j = 0; j < m; ++j) {
    x0[j] = det_bn_mod(kSeed, j, "full_ot_x0", q);
    x1[j] = det_bn_mod(kSeed, j, "full_ot_x1", q);
  }

  std::vector<buf_t> x_bin;
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(x0, x1, l));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Det_FullOT2P_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j;
  }
}

// Fixed expected receiver output for OT_Det.SenderOneInputRandomOT2P (kSeed, m=4).
static const char* kOT_Det_SenderOneInputRandomOT2P_expected_hex[] = {
    "e9ffcb5d576bb253d617fa484b1e1d1b0ae2becca11737b3ad556751b90e15db",
    "8784076e6f64f92de0260994911c1576dfb1a35b2bb5c2fbf5be35277461d1e5",
    "8fa7ae3de8688234cb35f2d1ec5fd113715850d6452c61e970e1442146360abf",
    "36398308e8340ded94ce4179c34c94d111fbb9a42149ee53953e3647109b3488",
};

// Fixed expected receiver output for OT_Det.SenderOneInputRandomOT2P_FixedParams.
// Deterministic output from fixed sid, delta=(1,2,3,4), r=0x0b.
static const char* kOT_Det_SenderOneInputRandomOT2P_FixedParams_expected_hex[] = {
    "d24c3776714468992d8dccc90953ddfe960d7fbb368260b4ef8809ff8a38850b",
    "100030afea77c9cd3f821ad92d88e91ebaf29445717621646bc11dd23cf6cc19",
    "e89c1a595f08009f7d160d6bb55986a2f398b2819460a44106027b64c292c9bd",
    "be4b58fd995711d91f3d0285a0916b013d2acb1d722c3162c9308f2f14701413",
};

TEST(OT_Det, SenderOneInputRandomOT2P_FixedParams) {
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
  ot_protocol_pvw_ctx_det_t ot(curve);
  ot.base.sid = buf_from_hex("000102030405060708090a0b0c0d0e0f10");
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Det_SenderOneInputRandomOT2P_FixedParams_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j
                                  << " expected_hex=" << kOT_Det_SenderOneInputRandomOT2P_FixedParams_expected_hex[j];
  }
  for (int j = 0; j < m; ++j) {
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q) << "index j=" << j << " x1=x0+delta";
  }
}

TEST(OT_Det, SenderOneInputRandomOT2P) {
  const int m = 4;
  auto curve = crypto::curve_secp256k1;
  auto q = curve.order();
  int l = q.get_bits_count();
  ot_protocol_pvw_ctx_det_t ot(curve);
  ot.base.sid = det_buf(kSeed, 0, "sor_ot_sid", 128);
  bits_t r = det_bits(kSeed, "sor_ot_r", m * 8);
  std::vector<bn_t> delta(m);
  for (int j = 0; j < m; ++j) delta[j] = det_bn_mod(kSeed, j, "sor_ot_delta", q);

  std::vector<bn_t> x0, x1;
  std::vector<buf_t> x_bin;
  EXPECT_OK(ot.step1_S2R());
  EXPECT_OK(ot.step2_R2S(r, l));
  EXPECT_OK(ot.step3_S2R(delta, q, x0, x1));
  EXPECT_OK(ot.output_R(m, x_bin));

  ASSERT_EQ(static_cast<int>(x_bin.size()), m);
  for (int j = 0; j < m; ++j) {
    buf_t expected = buf_from_hex(kOT_Det_SenderOneInputRandomOT2P_expected_hex[j]);
    EXPECT_EQ(x_bin[j], expected) << "index j=" << j;
  }
  for (int j = 0; j < m; ++j) {
    EXPECT_EQ(x1[j], (x0[j] + delta[j]) % q) << "index j=" << j << " x1=x0+delta";
  }
}

}  // namespace
