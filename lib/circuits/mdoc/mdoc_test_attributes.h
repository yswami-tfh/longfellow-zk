// Copyright 2025 Google LLC.
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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_TEST_ATTRIBUTES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_TEST_ATTRIBUTES_H_

#include "circuits/mdoc/mdoc_zk.h"

namespace proofs {
namespace test {
static const RequestedAttribute age_over_18 = {
    {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    {0xf5},
    11,
    1,
    kPrimitive};

static const RequestedAttribute not_over_18 = {
    .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    .value = {0xf4},
    .id_len = 11,
    .value_len = 1,
    .type = kPrimitive};

static const RequestedAttribute familyname_mustermann = {
    .id = {'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e'},
    .value = {'M', 'u', 's', 't', 'e', 'r', 'm', 'a', 'n', 'n'},
    .id_len = 11,
    .value_len = 10,
    .type = kString};

static const RequestedAttribute birthdate_1971_09_01 = {
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .value = {'1', '9', '7', '1', '-', '0', '9', '-', '0', '1'},
    .id_len = 10,
    .value_len = 10,
    .type = kDate};

static const RequestedAttribute birthdate_1998_09_04 = {
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .value = {'1', '9', '9', '8', '-', '0', '9', '-', '0', '4'},
    .id_len = 10,
    .value_len = 10,
    .type = kDate};

static const RequestedAttribute height_175 = {
    {'h', 'e', 'i', 'g', 'h', 't'}, {0x18, 0xaf}, 6, 2, kInt};

static const RequestedAttribute issue_date_2024_03_15 = {
    {'i', 's', 's', 'u', 'e', '_', 'd', 'a', 't', 'e'},
    {'2', '0', '2', '4', '-', '0', '3', '-', '1', '5'},
    10,
    10,
    kDate};

}  // namespace test
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_TEST_ATTRIBUTES_H_
