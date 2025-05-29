#include <gtest/gtest.h>

#include <cbmpc/crypto/lagrange.h>
#include <cbmpc/crypto/secret_sharing.h>
#include <cbmpc/protocol/ecdsa_mp.h>

#include "utils/local_network/mpc_tester.h"
#include "utils/test_macros.h"

namespace {

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::mpc::ecdsampc;
using namespace coinbase::testutils;

std::vector<std::vector<int>> test_ot_role(int n) {
  std::vector<std::vector<int>> ot_role_map(n, std::vector<int>(n));
  for (int i = 0; i < n; i++) {
    ot_role_map[i][i] = ot_no_role;
  }

  for (int i = 0; i <= n - 1; i++) {
    for (int j = i + 1; j < n; j++) {
      ot_role_map[i][j] = ot_sender;
      ot_role_map[j][i] = ot_receiver;
    }
  }
  return ot_role_map;
}

class ECDSAMPCTHRESHOLD : public NetworkMPC {};
INSTANTIATE_TEST_SUITE_P(, ECDSAMPCTHRESHOLD, testing::Values(5));

TEST_P(ECDSAMPCTHRESHOLD, DKG) {
  // Hardwired for the test. If changed, many other things here should be changed
  // Also for simplicity of testing, we assume the first t parties are active
  int n = 5;
  int t = 3;

  ecurve_t curve = crypto::curve_secp256k1;
  const auto& G = curve.generator();
  mod_t q = curve.order();
  std::vector<eckey::key_share_mp_t> keyshares(n);
  std::vector<eckey::key_share_mp_t> new_keyshares(n);
  std::vector<crypto::mpc_pid_t> all_pids(n);
  std::vector<crypto::mpc_pid_t> active_pids(t);
  crypto::ss::party_map_t<party_idx_t> name_to_idx;
  party_set_t quorum_party_set;

  quorum_party_set.add(0);
  quorum_party_set.add(1);
  quorum_party_set.add(2);
  for (int i = 0; i < n; i++) {
    all_pids[i] = mpc_runner_t::test_pids[i];
  }
  for (int i = 0; i < all_pids.size(); i++) {
    std::cout << all_pids[i].to_string() << "\n";
  }

  for (int i = 0; i < t; i++) {
    active_pids[i] = all_pids[i];
    name_to_idx[all_pids[i].to_string()] = i;
  }

  buf_t sid_dkg = crypto::gen_random(16);
  buf_t sid_refresh = crypto::gen_random(16);

  crypto::ss::node_t* root_node = new crypto::ss::node_t(
      crypto::ss::node_e::AND, "", 0,
      {new crypto::ss::node_t(crypto::ss::node_e::THRESHOLD, "threshold-node", 3,
                              {
                                  new crypto::ss::node_t(crypto::ss::node_e::LEAF, all_pids[0].to_string()),  // active
                                  new crypto::ss::node_t(crypto::ss::node_e::LEAF, all_pids[1].to_string()),  // active
                                  new crypto::ss::node_t(crypto::ss::node_e::LEAF, all_pids[2].to_string()),
                                  new crypto::ss::node_t(crypto::ss::node_e::LEAF, all_pids[3].to_string()),
                                  new crypto::ss::node_t(crypto::ss::node_e::LEAF, all_pids[4].to_string()),
                              })});
  crypto::ss::ac_t ac;
  ac.G = G;
  ac.root = root_node;

  std::vector<std::shared_ptr<partner_t>> partners;
  std::vector<std::shared_ptr<local_data_transport_t>> data_transports;
  std::vector<std::shared_ptr<mpc_net_context_t>> net_contexts;

  partners.resize(n);
  data_transports.resize(n);
  net_contexts.resize(n);

  for (int i = 0; i < n; i++) {
    partners[i] = std::make_shared<partner_t>(i);
    net_contexts[i] = std::make_shared<mpc_net_context_t>(i);
    data_transports[i] = std::make_shared<local_data_transport_t>(net_contexts[i]);
  }
  for (int i = 0; i < n; i++) net_contexts[i]->init_with_peers(net_contexts);

  std::shared_ptr<mpc::job_session_mp_t> job;
  job = std::make_shared<mpc::job_session_mp_t>(mpc::party_idx_t(0), all_pids, nullptr, 0);

  job->set_network(0, std::make_shared<network_t>(data_transports[0]));
  
  eckey::dkg_mp_threshold_t dkg_threshold;
  error_t rv = dkg_threshold.dkg(*job, curve, sid_dkg, ac, quorum_party_set, keyshares[job->get_party_idx()]);
  ASSERT_EQ(rv, 0);

  // DKG is an n-party protocol
  // mpc_runner = std::make_unique<mpc_runner_t>(n);
  // mpc_runner->run_mpc([&curve, &keyshares, &quorum_party_set, &ac, &sid_dkg](mpc::job_mp_t& job) {
  //   eckey::dkg_mp_threshold_t dkg_threshold;
  //   EXPECT_OK(dkg_threshold.dkg(job, curve, sid_dkg, ac, quorum_party_set, keyshares[job.get_party_idx()]));
  // });

  // ASSERT_EQ(sid_dkg.size(), 16);

  // // Signing is a t-party protocol
  // mpc_runner = std::make_unique<mpc_runner_t>(t);
  // buf_t data = crypto::gen_random(32);
  // std::vector<std::vector<int>> ot_role_map = test_ot_role(t);
  // mpc_runner->run_mpc([&curve, &keyshares, &ac, &name_to_idx, &q, &t, &n, &data, &ot_role_map](mpc::job_mp_t& job) {
  //   eckey::key_share_mp_t additive_share;
  //   EXPECT_OK(
  //       keyshares[job.get_party_idx()].to_additive_share(job.get_party_idx(), ac, t, name_to_idx, additive_share));
  //   buf_t sig;
  //   error_t rv = sign(job, additive_share, data, party_idx_t(0), ot_role_map, sig);
  //   ASSERT_EQ(rv, 0);

  //   if (job.get_party_idx() == 0) {
  //     crypto::ecc_pub_key_t ecc_verify_key(additive_share.Q);
  //     EXPECT_OK(ecc_verify_key.verify(data, sig));
  //   }
  // });
}

}  // namespace