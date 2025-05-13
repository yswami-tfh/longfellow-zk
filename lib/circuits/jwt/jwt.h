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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_JWT_JWT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_JWT_JWT_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/base64/decode.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/jwt/jwt_constants.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/routing.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

template <class LogicCircuit, class Field, class EC>
class JWT {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Nat = typename Field::N;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;
  using EcdsaWitness = typename Ecdsa::Witness;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Flatsha =
      FlatSHA256Circuit<LogicCircuit,
                        BitPlucker<LogicCircuit, kSHAJWTPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;
  using vind = typename LogicCircuit::template bitvec<kJWTIndexBits>;

 public:
  struct OpenedAttribute {
    v8 attr[32]; /* 32b representing attribute name in be. */
    v8 v1[64];   /* 64b of attribute value */
  };

  class Witness {
   public:
    EltW r_, s_, e_;
    EcdsaWitness jwt_sig_;
    v8 preimage_[64 * kMaxJWTSHABlocks];
    v256 e_bits_;
    ShaBlockWitness sha_[kMaxJWTSHABlocks];
    v8 nb_; /* index of sha block that contains the real hash  */
    std::vector<vind> attr_ind_;
    std::vector<v8> attr_id_len_;
    std::vector<v8> attr_value_len_;
    vind payload_ind_, payload_len_;

    void input(QuadCircuit<Field>& Q, const LogicCircuit& lc, size_t na) {
      r_ = Q.input();
      s_ = Q.input();
      e_ = Q.input();
      jwt_sig_.input(Q);
      for (size_t i = 0; i < 64 * kMaxJWTSHABlocks; ++i) {
        preimage_[i] = lc.template vinput<8>();
      }
      e_bits_ = lc.template vinput<256>();
      for (size_t j = 0; j < kMaxJWTSHABlocks; ++j) {
        sha_[j].input(Q);
      }
      nb_ = lc.template vinput<8>();

      for (size_t j = 0; j < na; ++j) {
        attr_ind_.push_back(lc.template vinput<kJWTIndexBits>());
        attr_id_len_.push_back(lc.template vinput<8>());
        attr_value_len_.push_back(lc.template vinput<8>());
      }
      payload_ind_ = lc.template vinput<kJWTIndexBits>();
      payload_len_ = lc.template vinput<kJWTIndexBits>();
    }
  };

  explicit JWT(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order), sha_(lc), r_(lc) {}

  //  The assert_jwt_attributes circuit verifies the following claims:
  //    1. There exists a hash digest e and a signature (r,s) on e
  //       under the public key (pkX, pkY).
  //    2. There exists a msg, and the hash of msg is equal to e.
  //    3. The JWT message is decoded correctly from base64.
  //    4. The decoded message is equal to the payload.header.
  //    5. The header contains alg:ESP256. [TODO]
  //    6. The attributes occur as <ID>":"<VALUE>" in the payload.body.
  //
  // Note that the soundness of (6) relies on assumptions about the format of
  // the JWT. The issuer cannot add spaces, cannot escape quotes in the body,
  // and the character : should only appear as a separator.
  void assert_jwt_attributes(EltW pkX, EltW pkY,
                             OpenedAttribute oa[/* NUM_ATTR */],
                             Witness& vw) const {
    Ecdsa ecc(lc_, ec_, order_);

    ecc.verify_signature3(pkX, pkY, vw.e_, vw.jwt_sig_);

    sha_.assert_message_hash(kMaxJWTSHABlocks, vw.nb_, vw.preimage_, vw.e_bits_,
                             vw.sha_);
    lc_.vassert_is_bit(vw.e_bits_);

    // Check that the e_bits_ match the EltW for e used in the signature.
    auto twok = lc_.one();
    auto est = lc_.konst(0);
    for (size_t i = 0; i < 256; ++i) {
      est = lc_.axpy(&est, twok, lc_.eval(vw.e_bits_[i]));
      lc_.f_.add(twok, twok);
    }
    lc_.assert_eq(&est, vw.e_);

    // Assert the attribute equality
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings
    std::vector<v8> shift_buf(64 * kMaxJWTSHABlocks);

    // First shift the payload into the shift_buf.
    r_.shift(vw.payload_ind_, 64 * (kMaxJWTSHABlocks - 2), shift_buf.data(),
             64 * kMaxJWTSHABlocks, vw.preimage_, zz, 3);

    // Decode the entire payload. A possible improvement is to decode just
    // the portion necessary.
    std::vector<v8> dec_buf(64 * kMaxJWTSHABlocks);
    Base64Decoder<LogicCircuit> b64(lc_);
    b64.base64_rawurl_decode_len(shift_buf.data(), dec_buf.data(),
                                 64 * (kMaxJWTSHABlocks - 2), vw.payload_len_);

    // For each attribute, shift the decoded payload so that the
    // attribute is at the beginning of B. Verify the attribute id, the
    // json separator, the attribute value, and the end quote.
    for (size_t i = 0; i < vw.attr_ind_.size(); ++i) {
      v8 B[32 + 3 + 64 + 1];

      // Check that values of the attribute_id.
      r_.shift(vw.attr_ind_[i], 100, B, dec_buf.size(), dec_buf.data(), zz, 3);
      assert_string_eq(32, vw.attr_id_len_[i], B, oa[i].attr);

      r_.shift(vw.attr_id_len_[i], 100, B, 100, B, zz, 3);
      uint8_t sep[3] = {'"', ':', '"'};
      for (size_t i = 0; i < 3; ++i) {
        auto want_i = lc_.template vbit<8>(sep[i]);
        lc_.vassert_eq(&B[i], want_i);
      }

      auto three = lc_.template vbit<2>(3);
      r_.shift(three, 100, B, 100, B, zz, 3);

      assert_string_eq(64, vw.attr_value_len_[i], B, oa[i].v1);

      r_.shift(vw.attr_value_len_[i], 100, B, 100, B, zz, 3);

      auto end_quote = lc_.template vbit<8>('"');
      lc_.vassert_eq(&B[0], end_quote);
    }
  }

  void assert_string_eq(size_t max, const v8& len, const v8 got[/*max*/],
                        const v8 want[/*max*/]) const {
    for (size_t j = 0; j < max; ++j) {
      auto ll = lc_.vlt(j, len);
      auto same = lc_.eq(8, got[j].data(), want[j].data());
      lc_.assert_implies(&ll, same);
    }
  }

 private:
  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;
  Flatsha sha_;
  Routing<LogicCircuit> r_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_JWT_JWT_H_
