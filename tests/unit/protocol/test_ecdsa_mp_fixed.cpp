// Fixed-parameter test for ECDSA MP sign with t=5, k=3.
// Uses only static keyshares (hex); no threshold_dkg at test time.
// Includes tests for the step-wise sign API (ecdsa_mp_steps).

#include <gtest/gtest.h>

#include <cbmpc/core/strext.h>
#include <cbmpc/crypto/lagrange.h>
#include <cbmpc/crypto/secret_sharing.h>
#include <cbmpc/protocol/ecdsa_mp_steps.h>

#include "utils/local_network/mpc_runner.h"
#include "utils/test_macros.h"

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::mpc::ecdsampc;
using namespace coinbase::testutils;

namespace {

// t=5 parties total, k=3 threshold (3 parties in signing quorum).
static const int kT = 5;
static const int kK = 3;

// Hex format per keyshare: x_share (64 hex), Q (130 hex = 65-byte uncompressed), Qis for party-0..party-4 (5*130 hex).
static const int kXHexLen = 64;
static const int kPointHexLen = 130;  // secp256k1 uncompressed point = 65 bytes
static const int kKeyshareHexLen = kXHexLen + kPointHexLen + kT * kPointHexLen;

static std::vector<crypto::pname_t> fixed_pnames() { return {"party-0", "party-1", "party-2", "party-3", "party-4"}; }

static error_t keyshare_from_hex(const char* hex, ecurve_t curve, const std::vector<crypto::pname_t>& pnames,
                                 eckey::key_share_mp_t& key) {
  std::string s(hex);
  if (s.size() < static_cast<size_t>(kKeyshareHexLen)) return E_FORMAT;
  key.curve = curve;
  key.party_name = "";  // caller sets per-party
  std::string x_hex = s.substr(0, kXHexLen);
  key.x_share = crypto::bn_t::from_hex(x_hex.c_str());
  buf_t Q_buf;
  if (!strext::from_hex(Q_buf, s.substr(kXHexLen, kPointHexLen))) return E_FORMAT;
  if (key.Q.from_bin(curve, mem_t(Q_buf.data(), Q_buf.size()))) return E_FORMAT;
  key.Qis.clear();
  for (int i = 0; i < kT; i++) {
    buf_t Qi_buf;
    if (!strext::from_hex(Qi_buf, s.substr(kXHexLen + kPointHexLen + i * kPointHexLen, kPointHexLen))) return E_FORMAT;
    crypto::ecc_point_t Qi;
    if (Qi.from_bin(curve, mem_t(Qi_buf.data(), Qi_buf.size()))) return E_FORMAT;
    key.Qis[pnames[i]] = Qi;
  }
  return 0;
}

static std::vector<std::vector<int>> ot_role_map_t3() {
  const int n = kK;
  std::vector<std::vector<int>> ot_role_map(n, std::vector<int>(n));
  for (int i = 0; i < n; i++) ot_role_map[i][i] = ot_no_role;
  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      ot_role_map[i][j] = ot_sender;
      ot_role_map[j][i] = ot_receiver;
    }
  }
  return ot_role_map;
}

// Build AC and quorum sets for t=5, k=3 (THRESHOLD(3) of 5 parties; signing quorum = parties 0,1,2).
static void setup_ac_and_quorum_t5_k3(const std::vector<crypto::pname_t>& pnames, crypto::ss::ac_t& ac,
                                      party_set_t& quorum_party_set, std::set<crypto::pname_t>& quorum1) {
  const int n = kT;
  ac.G = crypto::curve_secp256k1.generator();
  for (int i = 0; i < n; i++) quorum_party_set.add(i);
  quorum1.insert(pnames[0]);
  quorum1.insert(pnames[1]);
  quorum1.insert(pnames[2]);
  ac.root = new crypto::ss::node_t(crypto::ss::node_e::THRESHOLD, "", 3,
                                   {new crypto::ss::node_t(crypto::ss::node_e::LEAF, pnames[0]),
                                    new crypto::ss::node_t(crypto::ss::node_e::LEAF, pnames[1]),
                                    new crypto::ss::node_t(crypto::ss::node_e::LEAF, pnames[2]),
                                    new crypto::ss::node_t(crypto::ss::node_e::LEAF, pnames[3]),
                                    new crypto::ss::node_t(crypto::ss::node_e::LEAF, pnames[4])});
}

// Static keyshares loaded once from kFixedKeysharesHex.
static std::vector<eckey::key_share_mp_t>* g_fixed_keyshares_t5_k3 = nullptr;

// Static hex keyshares (t=5, k=3) from a single threshold_dkg run; used only for loading.
static const char* kFixedKeysharesHex[kT] = {
    "941C7F1CBD4BD0266F90ECD99F8F13DFA41E473BCE76EDBA0B99BE366E34565A0418cf45a60ad1d16ad9adc640f26c25d171d3d5b6c5776085"
    "6b4d2501df463090fbad569cace829ef00682fb3fe1d64e7cc82c68221b3598b9af3c9eb4debc01a04aaf7c5260483996bad4fa7e136b9a7d9"
    "45b794d776cd7ed0719324bb077327675d83dbfd453d9d04ef59514302b0e6f2736c8dda0a3314e80ca64143e8ce9cea0451e76cece7a96a09"
    "60656ac41d512657549c05d3970e619d7866d22b0185e806b70aa018305c950570080dddddb64d25fdaa8fece11c01581ce3695ce34b867204"
    "32d7bbfc039754fd61726d4b8205c79c886ad543683ed3d2c60039d39b6010b89587b7a9ce3023e1473d0b5352c2d74fccdf927a19c1548fd5"
    "c50c4d8c364ef3044c489287429791b1a1fba4937273d3ae6b90052d0a8d4655a6ca7a1fdb015c5a5076d81e25548cdf5257dfa6c9b28b0638"
    "a89689e7c997de94139f6977c75b030414c350fea41d6a75bd1361948ad4d9bf83d844684087ba58e68afcc7d1d9b515f8e03196cb3bf4f696"
    "0263347c580cb04b5939b68f7032505df2c487584c387d",  // party-0
    "F7F00E73A06B3AFF39F09DFDF57EBB1DB21054EF89801AD8BBD44A44BF971FB40418cf45a60ad1d16ad9adc640f26c25d171d3d5b6c5776085"
    "6b4d2501df463090fbad569cace829ef00682fb3fe1d64e7cc82c68221b3598b9af3c9eb4debc01a04aaf7c5260483996bad4fa7e136b9a7d9"
    "45b794d776cd7ed0719324bb077327675d83dbfd453d9d04ef59514302b0e6f2736c8dda0a3314e80ca64143e8ce9cea0451e76cece7a96a09"
    "60656ac41d512657549c05d3970e619d7866d22b0185e806b70aa018305c950570080dddddb64d25fdaa8fece11c01581ce3695ce34b867204"
    "32d7bbfc039754fd61726d4b8205c79c886ad543683ed3d2c60039d39b6010b89587b7a9ce3023e1473d0b5352c2d74fccdf927a19c1548fd5"
    "c50c4d8c364ef3044c489287429791b1a1fba4937273d3ae6b90052d0a8d4655a6ca7a1fdb015c5a5076d81e25548cdf5257dfa6c9b28b0638"
    "a89689e7c997de94139f6977c75b030414c350fea41d6a75bd1361948ad4d9bf83d844684087ba58e68afcc7d1d9b515f8e03196cb3bf4f696"
    "0263347c580cb04b5939b68f7032505df2c487584c387d",  // party-1
    "1F9BA494FF6995AA1B9E52060FD44BDD904BC7D8536D65821A3F9C903845AD440418cf45a60ad1d16ad9adc640f26c25d171d3d5b6c5776085"
    "6b4d2501df463090fbad569cace829ef00682fb3fe1d64e7cc82c68221b3598b9af3c9eb4debc01a04aaf7c5260483996bad4fa7e136b9a7d9"
    "45b794d776cd7ed0719324bb077327675d83dbfd453d9d04ef59514302b0e6f2736c8dda0a3314e80ca64143e8ce9cea0451e76cece7a96a09"
    "60656ac41d512657549c05d3970e619d7866d22b0185e806b70aa018305c950570080dddddb64d25fdaa8fece11c01581ce3695ce34b867204"
    "32d7bbfc039754fd61726d4b8205c79c886ad543683ed3d2c60039d39b6010b89587b7a9ce3023e1473d0b5352c2d74fccdf927a19c1548fd5"
    "c50c4d8c364ef3044c489287429791b1a1fba4937273d3ae6b90052d0a8d4655a6ca7a1fdb015c5a5076d81e25548cdf5257dfa6c9b28b0638"
    "a89689e7c997de94139f6977c75b030414c350fea41d6a75bd1361948ad4d9bf83d844684087ba58e68afcc7d1d9b515f8e03196cb3bf4f696"
    "0263347c580cb04b5939b68f7032505df2c487584c387d",  // party-2
    "9D47B5B4C3C2A8039B2E0C8FE43B9FDA59B816440E321E0E5CC4F67D45A73AB80418cf45a60ad1d16ad9adc640f26c25d171d3d5b6c5776085"
    "6b4d2501df463090fbad569cace829ef00682fb3fe1d64e7cc82c68221b3598b9af3c9eb4debc01a04aaf7c5260483996bad4fa7e136b9a7d9"
    "45b794d776cd7ed0719324bb077327675d83dbfd453d9d04ef59514302b0e6f2736c8dda0a3314e80ca64143e8ce9cea0451e76cece7a96a09"
    "60656ac41d512657549c05d3970e619d7866d22b0185e806b70aa018305c950570080dddddb64d25fdaa8fece11c01581ce3695ce34b867204"
    "32d7bbfc039754fd61726d4b8205c79c886ad543683ed3d2c60039d39b6010b89587b7a9ce3023e1473d0b5352c2d74fccdf927a19c1548fd5"
    "c50c4d8c364ef3044c489287429791b1a1fba4937273d3ae6b90052d0a8d4655a6ca7a1fdb015c5a5076d81e25548cdf5257dfa6c9b28b0638"
    "a89689e7c997de94139f6977c75b030414c350fea41d6a75bd1361948ad4d9bf83d844684087ba58e68afcc7d1d9b515f8e03196cb3bf4f696"
    "0263347c580cb04b5939b68f7032505df2c487584c387d",  // party-3
    "B3CCFC6FE2AA650688B58CE002DD35C0375DA47ADC8A508C9517A10D4B470BF00418cf45a60ad1d16ad9adc640f26c25d171d3d5b6c5776085"
    "6b4d2501df463090fbad569cace829ef00682fb3fe1d64e7cc82c68221b3598b9af3c9eb4debc01a04aaf7c5260483996bad4fa7e136b9a7d9"
    "45b794d776cd7ed0719324bb077327675d83dbfd453d9d04ef59514302b0e6f2736c8dda0a3314e80ca64143e8ce9cea0451e76cece7a96a09"
    "60656ac41d512657549c05d3970e619d7866d22b0185e806b70aa018305c950570080dddddb64d25fdaa8fece11c01581ce3695ce34b867204"
    "32d7bbfc039754fd61726d4b8205c79c886ad543683ed3d2c60039d39b6010b89587b7a9ce3023e1473d0b5352c2d74fccdf927a19c1548fd5"
    "c50c4d8c364ef3044c489287429791b1a1fba4937273d3ae6b90052d0a8d4655a6ca7a1fdb015c5a5076d81e25548cdf5257dfa6c9b28b0638"
    "a89689e7c997de94139f6977c75b030414c350fea41d6a75bd1361948ad4d9bf83d844684087ba58e68afcc7d1d9b515f8e03196cb3bf4f696"
    "0263347c580cb04b5939b68f7032505df2c487584c387d",  // party-4
};

static std::vector<eckey::key_share_mp_t>& get_fixed_keyshares_t5_k3() {
  if (g_fixed_keyshares_t5_k3 != nullptr) return *g_fixed_keyshares_t5_k3;
  static std::vector<eckey::key_share_mp_t> keyshares(kT);
  const std::vector<crypto::pname_t> pnames = fixed_pnames();
  ecurve_t curve = crypto::curve_secp256k1;
  for (int i = 0; i < kT; i++) {
    error_t load_err = keyshare_from_hex(kFixedKeysharesHex[i], curve, pnames, keyshares[i]);
    EXPECT_EQ(0, load_err);
    keyshares[i].party_name = pnames[i];
  }
  g_fixed_keyshares_t5_k3 = &keyshares;
  return keyshares;
}

// --- Tests for step-wise sign API (ecdsa_mp_steps) ---

// Run full sign using step-wise API with static keyshares only (no DKG at test time).
// t=5, k=3: keyshares from get_fixed_keyshares_t5_k3(), then sign with 3 parties via step functions.
TEST(ECDSAMPFixed, SignSteps_T5_K3_FullSignViaSteps) {
  const int n = kT;
  std::vector<crypto::pname_t> pnames = fixed_pnames();
  std::map<crypto::pname_t, int> quorum_party_map;
  for (int i = 0; i < n; i++) quorum_party_map[pnames[i]] = i;

  crypto::ss::ac_t ac;
  party_set_t quorum_party_set;
  std::set<crypto::pname_t> quorum1;
  setup_ac_and_quorum_t5_k3(pnames, ac, quorum_party_set, quorum1);

  std::vector<eckey::key_share_mp_t>& keyshares = get_fixed_keyshares_t5_k3();

  buf_t data = crypto::gen_random(32);
  std::vector<std::vector<int>> ot_role_map = ot_role_map_t3();
  mpc_runner_t quorum_runner({"party-0", "party-1", "party-2"});

  quorum_runner.run_mpc([&](mpc::job_mp_t& job) {
    eckey::key_share_mp_t additive_share;
    EXPECT_OK(keyshares[quorum_party_map[job.get_name()]].to_additive_share(ac, quorum1, additive_share));

    sign_ctx_t* ctx = sign_ctx_create();
    ASSERT_NE(ctx, nullptr);
    error_t rv = sign_validate_and_begin(job, additive_share, data, party_idx_t(0), ot_role_map, *ctx);
    if (rv == 0) rv = sign_step_1(job, *ctx);
    if (rv == 0) rv = sign_step_2(job, *ctx);
    if (rv == 0) rv = sign_step_3(job, *ctx);
    if (rv == 0) rv = sign_step_4(job, *ctx);
    if (rv == 0) rv = sign_step_5(job, *ctx);
    if (rv == 0) rv = sign_step_6(job, *ctx);
    if (rv == 0) rv = sign_step_7(job, *ctx);
    if (rv == 0) rv = sign_step_8(job, *ctx);
    if (rv == 0) rv = sign_step_9(job, *ctx);
    buf_t sig;
    if (rv == 0) rv = sign_step_10(job, *ctx, sig);
    sign_ctx_destroy(ctx);

    ASSERT_EQ(rv, 0);
    if (job.get_party_idx() == 0) {
      crypto::ecc_pub_key_t ecc_verify_key(additive_share.Q);
      EXPECT_OK(ecc_verify_key.verify(data, sig));
    }
  });
}

}  // namespace