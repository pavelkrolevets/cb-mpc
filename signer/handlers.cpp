#include <chrono>
#include <iostream>
#include <shared_mutex>
#include <sstream>

#include <cbmpc/crypto/lagrange.h>
#include <cbmpc/crypto/secret_sharing.h>
#include <cbmpc/protocol/ecdsa_mp.h>
#include <cbmpc/protocol/mpc_job.h>

#include "httplib.h"
#include "json.hpp"
#include "mpc_runner.h"

using namespace coinbase;
using namespace coinbase::mpc;
using namespace coinbase::mpc::ecdsampc;
using json = nlohmann::json;

using namespace signer;

void generate_key_handler(httplib::Server &srv, int &id) {
  srv.Post("/start_dkg", [&](const httplib::Request &req, httplib::Response &res) {
    auto j = json::parse(req.body);
    std::cout << "Received request to generate commits: \n" << j.dump(4) << std::endl;
    if (!j.contains("keyid")) {
      std::cout << "Error: no keyid provided: \n" << j.dump(4) << std::endl;
      return;
    }

    std::string keyid = j["keyid"];
    std::vector<crypto::mpc_pid_t> all_pids{
        crypto::pid_from_name("test party 1"), crypto::pid_from_name("test party 2"),
        crypto::pid_from_name("test party 3"), crypto::pid_from_name("test party 4"),
        crypto::pid_from_name("test party 5")};

    // create job session
    int n = all_pids.size();
    int t = 3;

    ecurve_t curve = crypto::curve_secp256k1;
    const auto &G = curve.generator();
    mod_t q = curve.order();
    eckey::key_share_mp_t keyshare;
    party_set_t quorum_party_set;

    buf_t sid_dkg = crypto::gen_random(16);
    buf_t sid_refresh = crypto::gen_random(16);

    crypto::ss::node_t *root_node = new crypto::ss::node_t(
        crypto::ss::node_e::AND, "", 0,
        {new crypto::ss::node_t(
            crypto::ss::node_e::THRESHOLD, "threshold-node", t,
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
    error_t rv = dkg_threshold.dkg(*job, curve, sid_dkg, ac, quorum_party_set, keyshare);
  });
}
