window.BENCHMARK_DATA = {
  "lastUpdate": 1742577983537,
  "repoUrl": "https://github.com/coinbase/cb-mpc",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "Arash-Afshar@users.noreply.github.com",
            "name": "Arash Afshar",
            "username": "Arash-Afshar"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3e545471b7e44a4f1858c6729184d6d4cccd6f50",
          "message": "feat: first release (#3)",
          "timestamp": "2025-03-21T10:42:58-06:00",
          "tree_id": "a14267dcc1c4572d5df58c559399a4a0ec47d107",
          "url": "https://github.com/coinbase/cb-mpc/commit/3e545471b7e44a4f1858c6729184d6d4cccd6f50"
        },
        "date": 1742577982896,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BP/Paillier/Gen",
            "value": 50677.50133332538,
            "unit": "us/iter",
            "extra": "iterations: 12\ncpu: 50674.83366666667 us\nthreads: 1"
          },
          {
            "name": "BP/Paillier/Enc",
            "value": 4510.268438711899,
            "unit": "us/iter",
            "extra": "iterations: 155\ncpu: 4510.072058064515 us\nthreads: 1"
          },
          {
            "name": "BP/Paillier/Pub-Enc",
            "value": 8584.010170735137,
            "unit": "us/iter",
            "extra": "iterations: 82\ncpu: 8582.526256097559 us\nthreads: 1"
          },
          {
            "name": "BP/Paillier/Dec",
            "value": 4524.982877419168,
            "unit": "us/iter",
            "extra": "iterations: 155\ncpu: 4524.702199999997 us\nthreads: 1"
          },
          {
            "name": "BP/Paillier/Add",
            "value": 11.027765286831732,
            "unit": "us/iter",
            "extra": "iterations: 63486\ncpu: 11.026958211259174 us\nthreads: 1"
          },
          {
            "name": "BP/Paillier/Add-Scalar",
            "value": 13.040747751883424,
            "unit": "us/iter",
            "extra": "iterations: 54490\ncpu: 13.040027069187001 us\nthreads: 1"
          },
          {
            "name": "BP/Paillier/Mul-Scalar",
            "value": 8316.324238096839,
            "unit": "us/iter",
            "extra": "iterations: 84\ncpu: 8315.720809523813 us\nthreads: 1"
          }
        ]
      }
    ]
  }
}