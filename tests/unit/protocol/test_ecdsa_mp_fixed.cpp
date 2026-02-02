// Fixed-parameter test for ECDSA MP sign with t=5, k=3.
// Flow is split into separate steps: Step 1 = threshold DKG (5 parties), Step 2 = sign (3 parties).
// Does not use NetworkMPC/mpc_job fixture; uses mpc_runner_t directly.
// Includes tests for the step-wise sign API (ecdsa_mp_steps).

#include <gtest/gtest.h>

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

static std::vector<crypto::pname_t> fixed_pnames() { return {"party-0", "party-1", "party-2", "party-3", "party-4"}; }

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

// --- Tests for step-wise sign API (ecdsa_mp_steps) ---

// Run full sign using step-wise API (sign_ctx_create, sign_validate_and_begin, sign_step_1..10, sign_ctx_destroy).
// t=5, k=3: DKG with 5 parties, then sign with 3 parties via step functions.
TEST(ECDSAMPFixed, SignSteps_T5_K3_FullSignViaSteps) {
  const int n = kT;
  std::vector<crypto::pname_t> pnames = fixed_pnames();
  std::map<crypto::pname_t, int> quorum_party_map;
  for (int i = 0; i < n; i++) quorum_party_map[pnames[i]] = i;

  ecurve_t curve = crypto::curve_secp256k1;
  std::vector<eckey::key_share_mp_t> keyshares(n);
  crypto::ss::ac_t ac;
  ac.G = curve.generator();
  party_set_t quorum_party_set;
  std::set<crypto::pname_t> quorum1;
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

  buf_t sid_dkg = crypto::gen_random(16);
  mpc_runner_t all_parties_runner(pnames);
  all_parties_runner.run_mpc([&](mpc::job_mp_t& job) {
    EXPECT_OK(eckey::key_share_mp_t::threshold_dkg(job, curve, sid_dkg, ac, quorum_party_set,
                                                   keyshares[job.get_party_idx()]));
  });

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