// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// main() for running both tests and benchmarks in the same
// file.
//
// The behavior is as follows:
//
//   foo_test
//       Run tests but not benchmarks
//
//   foo_test --benchmark_filter=all
//       Run benchmarks but not tests
//
#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <string.h>

int main(int argc, char **argv) {
  // Before InitGoogleTest(), check whether we are in
  // cmake's gtest_discover_tests().  Must do this first
  // because InitGoogleTest() consumes the argv[] entry.
  bool gtest_discover = (argc == 2) && !strcmp(argv[1], "--gtest_list_tests");

  testing::InitGoogleTest(&argc, argv);

  // Do not attempt to run benchmarks with --gtest_list_tests,
  // as this confuses gtest_discover_tests().
  if (!gtest_discover) {
    // By default run no benchmarks
    benchmark::Initialize(&argc, argv);
    auto bf = benchmark::GetBenchmarkFilter();

    if (bf != "") {
      size_t matches = benchmark::RunSpecifiedBenchmarks();
      benchmark::Shutdown();

      if (matches > 0) {
        // run benchmarks only and not tests
        return 0;
      }
    }
  }

  return RUN_ALL_TESTS();
}
