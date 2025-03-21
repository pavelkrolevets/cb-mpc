window.BENCHMARK_DATA = {
  "lastUpdate": 1742577977792,
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
        "date": 1742577976780,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "Core/BN/ModAdd/256",
            "value": 0.0689495747207143,
            "unit": "us/iter",
            "extra": "iterations: 10785265\ncpu: 0.06889960024162597 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModAdd/4096",
            "value": 0.27184722132440914,
            "unit": "us/iter",
            "extra": "iterations: 2614213\ncpu: 0.2718297154822526 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModSubtract/256",
            "value": 0.05956496115758171,
            "unit": "us/iter",
            "extra": "iterations: 11736906\ncpu: 0.05955836947147712 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModSubtract/4096",
            "value": 0.3219511270269253,
            "unit": "us/iter",
            "extra": "iterations: 2162770\ncpu: 0.3219346023849032 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModMultiply/256",
            "value": 0.15217459046637014,
            "unit": "us/iter",
            "extra": "iterations: 4542728\ncpu: 0.1521660658529419 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModMultiply/4096",
            "value": 10.944231997354326,
            "unit": "us/iter",
            "extra": "iterations: 63449\ncpu: 10.943258286182495 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModExponentiate/256",
            "value": 16.30634100135384,
            "unit": "us/iter",
            "extra": "iterations: 42862\ncpu: 16.30560013531778 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModExponentiate/4096",
            "value": 16514.209857145295,
            "unit": "us/iter",
            "extra": "iterations: 42\ncpu: 16513.879595237988 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModInvert/256",
            "value": 17.345175812381814,
            "unit": "us/iter",
            "extra": "iterations: 40037\ncpu: 17.340283287958737 us\nthreads: 1"
          },
          {
            "name": "Core/BN/ModInvert/4096",
            "value": 724.7319522821084,
            "unit": "us/iter",
            "extra": "iterations: 964\ncpu: 724.7079273858892 us\nthreads: 1"
          },
          {
            "name": "Core/BN/GCD/256",
            "value": 23.262983009062314,
            "unit": "us/iter",
            "extra": "iterations: 30428\ncpu: 23.261372288681088 us\nthreads: 1"
          },
          {
            "name": "Core/BN/GCD/4096",
            "value": 1132.6749067794187,
            "unit": "us/iter",
            "extra": "iterations: 590\ncpu: 1132.6313644067766 us\nthreads: 1"
          },
          {
            "name": "Core/BN/GCD-RSA-Modulus/256",
            "value": 22.914513218118508,
            "unit": "us/iter",
            "extra": "iterations: 30375\ncpu: 22.911947456790166 us\nthreads: 1"
          },
          {
            "name": "Core/BN/GCD-RSA-Modulus/4096",
            "value": 1138.4899515344434,
            "unit": "us/iter",
            "extra": "iterations: 619\ncpu: 1138.389878836821 us\nthreads: 1"
          },
          {
            "name": "Core/BN/GCD-Batch(16)RSA-Modulus/256",
            "value": 25.857362074060717,
            "unit": "us/iter",
            "extra": "iterations: 27058\ncpu: 25.8562280286794 us\nthreads: 1"
          },
          {
            "name": "Core/BN/GCD-Batch(16)RSA-Modulus/4096",
            "value": 1306.3884283053815,
            "unit": "us/iter",
            "extra": "iterations: 537\ncpu: 1306.3007094972006 us\nthreads: 1"
          }
        ]
      }
    ]
  }
}