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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_JWT_JWT_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_JWT_JWT_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/base64/decode_util.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/jwt/jwt_constants.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "util/log.h"

namespace proofs {

/* This struct allows a verifier to express which attribute and value the prover
 * must claim. */
struct OpenedAttribute {
  uint8_t id[32];
  uint8_t value[64];
  size_t id_len, value_len;
};

template <class EC, class ScalarField>
class JWTWitness {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EcdsaWitness = VerifyWitness3<EC, ScalarField>;
  const EC& ec_;

 public:
  Elt e_, r_, s_;
  EcdsaWitness sig_;

  uint8_t preimage_[64 * kMaxJWTSHABlocks];
  uint8_t e_bits_[256];
  FlatSHA256Witness::BlockWitness sha_bw_[kMaxJWTSHABlocks];
  uint8_t numb_; /* Number of the correct sha block. */
  uint8_t na_;   /* Number of attributes. */
  size_t payload_ind_, payload_len_;
  std::vector<size_t> attr_ind_;
  std::vector<size_t> attr_id_len_;
  std::vector<size_t> attr_value_len_;

  explicit JWTWitness(const EC& ec, const ScalarField& Fn)
      : ec_(ec), sig_(Fn, ec) {}

  void fill_witness(DenseFiller<Field>& filler) const {
    filler.push_back(r_);
    filler.push_back(s_);
    filler.push_back(e_);
    sig_.fill_witness(filler);

    // Write the message.
    for (size_t i = 0; i < 64 * kMaxJWTSHABlocks; ++i) {
      filler.push_back(preimage_[i], 8, ec_.f_);
    }

    for (size_t i = 0; i < 256; ++i) {
      filler.push_back(e_bits_[i], 1, ec_.f_);
    }

    for (size_t j = 0; j < kMaxJWTSHABlocks; ++j) {
      fill_sha(filler, sha_bw_[j]);
    }

    filler.push_back(numb_, 8, ec_.f_);

    for (size_t i = 0; i < na_; ++i) {
      filler.push_back(attr_ind_[i], kJWTIndexBits, ec_.f_);
      filler.push_back(attr_id_len_[i], 8, ec_.f_);
      filler.push_back(attr_value_len_[i], 8, ec_.f_);
    }

    filler.push_back(payload_ind_, kJWTIndexBits, ec_.f_);
    filler.push_back(payload_len_, kJWTIndexBits, ec_.f_);
  }

  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, kSHAJWTPluckerBits> BPENC(ec_.f_);
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
      filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
    }
  }

  // Transform from u32 be (i.e., be[0] is the most significant nibble)
  // into nat form, which requires first converting to le byte order.
  Nat nat_from_u32(const uint32_t be[]) const {
    uint8_t tmp[Nat::kBytes];
    const size_t top = Nat::kBytes / 4;
    for (size_t i = 0; i < Nat::kBytes; ++i) {
      tmp[i] = (be[top - i / 4 - 1] >> ((i % 4) * 8)) & 0xff;
    }
    return Nat::of_bytes(tmp);
  }

  // Transform from u8 be (i.e., be[31] is the most significant byte) into
  // nat form, which requires first converting to le byte order.
  Nat nat_from_be(const uint8_t be[/* Nat::kBytes */]) {
    uint8_t tmp[Nat::kBytes];
    // Transform into byte-wise le representation.
    for (size_t i = 0; i < Nat::kBytes; ++i) {
      tmp[i] = be[Nat::kBytes - i - 1];
    }
    return Nat::of_bytes(tmp);
  }

  bool compute_witness(std::string jwt, Elt pkX, Elt pkY,
                       std::vector<OpenedAttribute> attrs) {
    size_t dot = jwt.find_first_of('.');
    size_t dot2 = jwt.find_first_of('.', dot + 1);
    if (dot == std::string::npos || dot2 == std::string::npos) {
      log(ERROR, "JWT is not in the format of header.payload.signature");
      return false;
    }
    auto hdr = jwt.substr(0, dot);
    auto pld = jwt.substr(dot + 1, dot2 - dot - 1);
    auto rest = jwt.substr(dot2 + 1);
    auto msg = jwt.substr(0, dot2);
    payload_len_ = pld.size();
    payload_ind_ = dot + 1;

    if (payload_len_ > kMaxJWTSHABlocks * 64) {
      log(ERROR, "JWT payload is too large");
      return false;
    }

    size_t tilde = rest.find_first_of('~');
    if (tilde == std::string::npos) {
      log(ERROR, "JWT is not in the format of header.payload.signature~epoch");
      return false;
    }
    auto sig = rest.substr(0, tilde);
    auto claims = rest.substr(tilde + 1);

    FlatSHA256Witness::transform_and_witness_message(
        msg.size(), reinterpret_cast<const uint8_t*>(msg.data()),
        kMaxJWTSHABlocks, numb_, preimage_, sha_bw_);

    Nat ne = nat_from_u32(sha_bw_[numb_ - 1].h1);
    e_ = ec_.f_.to_montgomery(ne);

    std::vector<uint8_t> sigb;
    sigb.reserve(ec_.f_.kBytes * 2);
    if (!base64_decode_url(sig, sigb) || sigb.size() < ec_.f_.kBytes * 2) {
      log(ERROR, "signature is not in the format of base64url");
      return false;
    }
    Nat nr = nat_from_be(&sigb[0]);
    Nat ns = nat_from_be(&sigb[ec_.f_.kBytes]);

    r_ = ec_.f_.to_montgomery(nr);
    s_ = ec_.f_.to_montgomery(ns);
    if (!sig_.compute_witness(pkX, pkY, ne, nr, ns)) {
      log(ERROR, "signature verification failed");
      return false;
    }

    for (size_t i = 0; i < 256; ++i) {
      e_bits_[i] = ne.bit(i);
    }

    // Find the positions of each of the attributes.
    na_ = attrs.size();
    std::vector<uint8_t> payload;
    payload.reserve(pld.size());
    if (!base64_decode_url(pld, payload)) {
      log(ERROR, "JWT payload is not in the format of base64url");
      return false;
    }
    std::string str((const char*)payload.data(), payload.size());
    for (size_t i = 0; i < na_; ++i) {
      size_t ind = str.find((const char*)attrs[i].id, 0, attrs[i].id_len);
      if (ind == std::string::npos) {
        log(ERROR, "Could not find attribute %.*s", attrs[i].id_len,
            attrs[i].id);
        return false;
      }
      size_t vstart = ind + attrs[i].id_len + 3;
      size_t vind =
          str.find((const char*)attrs[i].value, vstart, attrs[i].value_len);
      if (vind == std::string::npos || vind != vstart) {
        log(ERROR, "Could not find attribute value %.*s", attrs[i].value_len,
            attrs[i].value);
        return false;
      }
      attr_ind_.push_back(ind);
      attr_id_len_.push_back(attrs[i].id_len);
      attr_value_len_.push_back(attrs[i].value_len);
    }

    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_JWT_JWT_WITNESS_H_
