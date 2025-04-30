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

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "circuits/mdoc/mdoc_zk.h"
#include "util/crypto.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

TEST(ZkSpecTest, FindZkSpec) {
  const ZkSpecStruct& zk_spec = kZkSpecs[0];

  const ZkSpecStruct* found_zk_spec =
      find_zk_spec("longfellow-libzk-v1", zk_spec.circuit_hash);
  EXPECT_NE(found_zk_spec, nullptr);
  EXPECT_EQ(found_zk_spec->system, zk_spec.system);
  EXPECT_EQ(found_zk_spec->circuit_hash, zk_spec.circuit_hash);
  EXPECT_EQ(found_zk_spec->num_attributes, zk_spec.num_attributes);
  EXPECT_EQ(found_zk_spec->version, zk_spec.version);
}

TEST(ZkSpecTest, ReturnNullptrIfNoMatchingZkSpecFound) {
  const ZkSpecStruct* zk_spec = find_zk_spec(
      "longfellow-libzk-v1",
      "1234567890123456789012345678901234567890123456789012345678901234");
  EXPECT_EQ(zk_spec, nullptr);
}

void test_circuit_hash(size_t num_attributes) {
  ZkSpecStruct zk_spec = {};
  uint8_t* circuit;
  size_t circuit_len;
  zk_spec.num_attributes = num_attributes;
  auto ret = generate_circuit(&zk_spec, &circuit, &circuit_len);
  EXPECT_EQ(ret, CIRCUIT_GENERATION_SUCCESS);

  uint8_t cid[kSHA256DigestSize];
  EXPECT_TRUE(circuit_id(cid, circuit, circuit_len, &zk_spec));

  char buf[kSHA256DigestSize * 2 + 1] = {};
  hex_to_str(buf, cid, kSHA256DigestSize);
  log(INFO, "circuit hash %d attr:: %s", num_attributes, buf);

  bool found = false;
  for (size_t k = 0; k < kNumZkSpecs; ++k) {
    if (strcmp(kZkSpecs[k].circuit_hash, buf) == 0) {
      found = true;
      break;
    }
  }
  // Must use free because generate_circuit is a pure C library that allocates
  // with malloc.
  free(circuit);
  EXPECT_TRUE(found);
}

// These tests ensure that the current circuit hash for 1--4 attributes is
// included in the zk_spec data structure.
// They are defined separately so that they can run in parallel.
// They can be run using
//    blaze test -c opt --test_output=streamed  \
//        //circuits/mdoc:zk_spec_test
// in order to print out the new circuit hashes.
TEST(ZkSpecTest, CorrectSpecFor1Attribute) { test_circuit_hash(1); }

TEST(ZkSpecTest, CorrectSpecFor2Attributes) { test_circuit_hash(2); }

TEST(ZkSpecTest, CorrectSpecFor3Attributes) { test_circuit_hash(3); }

TEST(ZkSpecTest, CorrectSpecFor4Attributes) { test_circuit_hash(4); }

}  // namespace
}  // namespace proofs
