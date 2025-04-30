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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_CBOR_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_CBOR_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <vector>

#include "circuits/cbor_parser/cbor_constants.h"
#include "circuits/cbor_parser/cbor_pluck.h"
#include "circuits/cbor_parser/scan.h"
#include "circuits/logic/bit_adder.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/routing.h"
#include "util/panic.h"

namespace proofs {
template <class Logic>
class Cbor {
 public:
  using Field = typename Logic::Field;
  using EltW = typename Logic::EltW;
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;
  static constexpr size_t kIndexBits = CborConstants::kIndexBits;
  static constexpr size_t kNCounters = CborConstants::kNCounters;
  using bv_counters = typename Logic::template bitvec<kNCounters>;

  // a bitvector that contains an index into the input
  // (byte) array.
  using vindex = typename Logic::template bitvec<kIndexBits>;

  // does not yet work in binary fields
  static_assert(!Field::kCharacteristicTwo);

  explicit Cbor(const Logic& l)
      : l_(l), ba_count_(l), ba_byte_(l), ba_index_(l), bp_(l) {}

  struct global_witness {
    EltW invprod_decode;  // inverse of a certain product, see assert_decode()
    EltW cc0;             // initial value of counter[0]
    EltW invprod_parse;   // inverse of a certain product, see assert_parse()
  };

  struct position_witness {
    EltW encoded_sel_header;
  };

  //------------------------------------------------------------
  // Decoder (lexer)
  //------------------------------------------------------------
  struct decode {
    BitW arrayp;
    BitW mapp;
    BitW itemsp;
    BitW stringp;
    BitW tagp;
    BitW specialp;
    BitW simple_specialp;  // One of false, true, null, or undefined.
    BitW count0_23;
    BitW count24;
    BitW invalid;
    BitW length_plus_next_v8;
    BitW count_is_next_v8;
    BitW header;
    EltW length;  // of this item
    EltW as_field_element;
    EltW count_as_field_element;
    v8 as_bits;
  };

  // extract whatever we can from one v8
  struct decode decode_one_v8(const v8& v) const {
    const Logic& L = l_;  // shorthand
    struct decode s;
    L.vassert_is_bit(v);

    // v = type:3 count:5
    auto count = L.template slice<0, 5>(v);
    auto type = L.template slice<5, 8>(v);

    s.itemsp = L.veqmask(type, /*mask*/ 0b110, /*val*/ 0b100);
    s.stringp = L.veqmask(type, /*mask*/ 0b110, /*val*/ 0b010);

    s.specialp = L.veq(type, 7);
    s.tagp = L.veq(type, 6);
    s.arrayp = L.land(&s.itemsp, L.lnot(type[0]));
    s.mapp = L.land(&s.itemsp, type[0]);

    // count0_23 = (0 <= count < 24) = ~(count == 11xxx)
    s.count0_23 = L.lnot(L.veqmask(count, /*mask*/ 0b11000, /*val*/ 0b11000));

    s.count24 = L.veq(count, 24);

    BitW count20_23 = L.veqmask(count, /*mask*/ 0b11100, /*val*/ 0b10100);
    s.simple_specialp = L.land(&s.specialp, count20_23);

    // stringp && count24
    s.length_plus_next_v8 =
        L.veqmask(v, /*mask*/ 0b110'11111, /*val*/ 0b010'11000);

    // itemsp && count24
    s.count_is_next_v8 =
        L.veqmask(v, /*mask*/ 0b110'11111, /*val*/ 0b100'11000);

    // invalid = (specialp && !simple_specialp) || (!count24 && !count0_23)
    auto lhs = L.land(&s.specialp, L.lnot(s.simple_specialp));
    auto bad_count = L.lor_exclusive(&s.count24, s.count0_23);
    s.invalid = L.lor(&lhs, L.lnot(bad_count));

    s.count_as_field_element = ba_count_.as_field_element(count);

    // Length is the length of the item, including the header.
    //
    //    1          for header
    //   +1          if (count24)
    //   +count      if (stringp && count0_23);
    s.length = L.konst(1);
    s.length = L.add(&s.length, L.eval(s.count24));
    auto str_23 = L.land(&s.stringp, s.count0_23);
    auto e_str_23 = L.eval(str_23);
    auto adjust_if_string = L.mul(&e_str_23, s.count_as_field_element);
    s.length = L.add(&s.length, adjust_if_string);

    s.as_field_element = ba_byte_.as_field_element(v);
    s.as_bits = v;

    s.header = L.bit(0);  // for now
    return s;
  }

  void assert_decode(size_t n, const decode ds[/*n*/],
                     const position_witness pw[/*n*/],
                     const global_witness& gw) const {
    const Logic& L = l_;  // shorthand
    Scan<Logic> SC(l_);

    // -------------------------------------------------------------
    // Decoder didn't fail
    for (size_t i = 0; i < n; ++i) {
      L.assert_implies(&ds[i].header, L.lnot(ds[i].invalid));
    }
    // if LENGTH_PLUS_NEXT_V8 is TRUE in the last position,
    // then the input is invalid.
    L.assert_implies(&ds[n - 1].header, L.lnot(ds[n - 1].length_plus_next_v8));

    // if COUNT_IS_NEXT_V8 is TRUE in the last position,
    // then the input is invalid.
    L.assert_implies(&ds[n - 1].header, L.lnot(ds[n - 1].count_is_next_v8));

    // -------------------------------------------------------------
    // Headers are where they are supposed to be.
    // First, compute the segmented scan
    //   slen[i] = header[i] ? length[i] : (slen[i-1] + mone[i])
    std::vector<EltW> mone(n);
    std::vector<BitW> header(n);
    std::vector<EltW> length(n);
    std::vector<EltW> slen_next(n);

    for (size_t i = 0; i + 1 < n; ++i) {
      mone[i] = L.konst(L.mone());
      header[i] = ds[i].header;
      length[i] = ds[i].length;
      if (i + 1 < n) {
        auto len_i =
            L.lmul(&ds[i].length_plus_next_v8, ds[i + 1].as_field_element);
        length[i] = L.add(&length[i], len_i);
      }
    }

    SC.add(n, slen_next.data(), header.data(), length.data(), mone.data());

    // Now check the headers.
    {
      // "The first position is a header"
      L.assert1(header[0]);
    }

    {
      auto one = L.konst(1);
      // "\A I : (SLEN_NEXT[I] == 1)  IFF  HEADER[I+1]"
      {
        // "\A I : HEADER[I+1] => (SLEN_NEXT[I] == 1)"
        for (size_t i = 0; i + 1 < n; ++i) {
          auto implies = L.lmul(&header[i + 1], L.sub(&slen_next[i], one));
          L.assert0(implies);
        }
      }
      {
        // "\A I : (SLEN_NEXT[I] == 1) => HEADER[i+1] "
        // Verify via the invertibility of
        //
        //   PROD_{I, L} HEADER[I+1] ? 1 : (SLEN_NEXT[I] - 1)
        //
        auto f = [&](size_t i) {
          return L.mux(&header[i + 1], &one, L.sub(&slen_next[i], one));
        };
        EltW prod = L.mul(0, n - 1, f);
        auto want_one = L.mul(&prod, gw.invprod_decode);
        L.assert_eq(&want_one, one);
      }
    }
  }

  //------------------------------------------------------------
  // Parser
  //------------------------------------------------------------
  using counters = std::array<EltW, kNCounters>;
  struct parse_output {
    bv_counters sel;
    counters c;
  };

  void parse(size_t n, parse_output ps[/*n*/], const decode ds[/*n*/],
             const position_witness pw[/*n*/], const global_witness& gw) const {
    std::vector<EltW> ddss(n);
    std::vector<BitW> SS(n);
    std::vector<EltW> AA(n);
    std::vector<EltW> BB(n);

    const Logic& L = l_;  // shorthand
    Scan<Logic> SC(l_);

    for (size_t i = 0; i < n; ++i) {
      ps[i].sel = bp_.pluckj(pw[i].encoded_sel_header);
    }

    auto mone = L.konst(L.mone());
    for (size_t l = 0; l < kNCounters; ++l) {
      for (size_t i = 0; i < n; ++i) {
        // at the selected headers, decrement the level-L counter.
        auto dp = L.land(&ds[i].header, ps[i].sel[l]);
        ddss[i] = L.lmul(&dp, mone);
      }

      if (l == 0) {
        // do level-0 as an unsegmented parallel prefix
        // on DDSS starting at CC0.
        // One can achieve the same effect by using the segmented prefix
        // after initializing SS and AA as follows:
        //
        //   SS[0] = L.bit(1);
        //   AA[0] = gw.cc0;
        //   for (size_t i = 1; i < n; ++i) {
        //     SS[i] = L.bit(0);
        //     AA[i] = L.konst(0);
        //   }
        //
        // The compiler is smart enough to constant-fold the segment
        // SS[i] and produces the same circuit in both cases, but
        // there is no point in wasting compiler time and the
        // unsegmented prefix is more straightforward anyway.
        //
        // Note that AA, SS are uninitialized here.  They will be initialized
        // below for the next level.
        ddss[0] = gw.cc0;
        SC.add(n, BB.data(), ddss.data());
      } else {
        SC.add(n, BB.data(), SS.data(), AA.data(), ddss.data());
      }

      // output the result of the parallel prefix
      for (size_t i = 0; i < n; ++i) {
        ps[i].c[l] = BB[i];
      }

      // prepare SS, AA for the next level
      for (size_t i = 0; i < n; ++i) {
        EltW newc = L.eval(ds[i].tagp);
        EltW count = ds[i].count_as_field_element;
        if (i + 1 < n) {
          count = L.mux(&ds[i].count_is_next_v8, &ds[i + 1].as_field_element,
                        count);
        }
        newc = L.add(&newc, L.lmul(&ds[i].itemsp, count));
        newc = L.add(&newc, L.lmul(&ds[i].mapp, count));
        AA[i] = newc;

        auto sel = L.land(&ps[i].sel[l], ds[i].header);
        auto tag = L.lor(&ds[i].tagp, ds[i].itemsp);
        SS[i] = L.land(&sel, tag);
      }
    }

    // Assert that we don't want to start new segments at a level
    // that does not exist.
    for (size_t i = 0; i < n; ++i) {
      L.assert0(SS[i]);
    }
  }

  void assert_parse(size_t n, const decode ds[/*n*/],
                    const parse_output ps[/*n*/],
                    const global_witness& gw) const {
    const Logic& L = l_;  // shorthand

    for (size_t i = 0; i < n; ++i) {
      // "The SEL witnesses are mutually exclusive."
      // Verify by asserting that they are all bits
      // and that their sum (in the field) is a bit.
      auto sum = L.bit(0);
      for (size_t l = 0; l < kNCounters; ++l) {
        L.assert_is_bit(ps[i].sel[l]);
        sum = L.lor_exclusive(&sum, ps[i].sel[l]);
      }
      L.assert_is_bit(sum);

      // "at a header, at least one SEL bit is set"
      L.assert_implies(&ds[i].header, sum);
    }

    // "All counters are zero at the end of the input"
    // COUNTER[I][L] is the state of the parser at the end
    // of position I, so COUNTER[N-1][L] is the final state.
    for (size_t l = 0; l < kNCounters; ++l) {
      L.assert0(ps[n - 1].c[l]);
    }

    // SEL[0][0] is set.  We implicitly define COUNTER[-1][L] to make
    // this the correct choice.
    L.assert1(ps[0].sel[0]);

    for (size_t i = 0; i + 1 < n; ++i) {
      // "If SEL[I+1][L] is set, then COUNTER[I][L] is the nonzero
      // counter of maximal L.  (COUNTER[I][L] contains the output
      // counter of stage I, which affects SEL[I+1].)  Here we check
      // maximality:  COUNTER[I][J]=0 for J>L.  See below for
      // SEL[I+1][L] => (COUNTER[I][L] != 0).
      BitW b = ps[i + 1].sel[0];
      for (size_t l = 1; l < kNCounters; ++l) {
        // b => COUNTER[i][l] == 0
        L.assert0(L.lmul(&b, ps[i].c[l]));
        b = L.lor(&b, ps[i + 1].sel[l]);
      }
    }

    // "SEL[I+1][L] => (COUNTER[I][L] != 0)"
    // Check via the invertibility of
    //
    //    PROD_{I, L} SEL[I+1][L] ? COUNTER[I][L] : 1
    std::vector<EltW> prod(kNCounters);

    auto one = L.konst(1);
    for (size_t l = 0; l < kNCounters; ++l) {
      auto f = [&](size_t i) {
        return L.mux(&ps[i + 1].sel[l], &ps[i].c[l], one);
      };
      prod[l] = L.mul(0, n - 1, f);
    }

    EltW p = L.mul(0, kNCounters, [&](size_t l) { return prod[l]; });
    auto want_one = L.mul(&p, gw.invprod_parse);
    L.assert_eq(&want_one, one);
  }

  //------------------------------------------------------------
  // "J is the header of a string of length LEN containing BYTES"
  //------------------------------------------------------------
  void assert_text_at(size_t n, const vindex& j, size_t len,
                      const uint8_t bytes[/*len*/],
                      const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand
    const Routing<Logic> R(L);

    // we don't handle long strings
    proofs::check(len < 24, "len < 24");

    assert_header(n, j, ds);

    std::vector<EltW> A(n);
    for (size_t i = 0; i < n; ++i) {
      A[i] = ds[i].as_field_element;
    }

    // shift len+1 bytes, including the header.
    std::vector<EltW> B(len + 1);
    const EltW defaultA = L.konst(256);  // a constant that cannot appear in A[]
    R.shift(j, len + 1, B.data(), n, A.data(), defaultA, /*unroll=*/3);

    size_t expected_header = (3 << 5) + len;
    L.assert_eq(&B[0], L.konst(expected_header));
    for (size_t i = 0; i < len; ++i) {
      auto bi = L.konst(bytes[i]);
      L.assert_eq(&B[i + 1], bi);
    }
  }

  //------------------------------------------------------------
  // "J is a header containing unsigned U."
  //------------------------------------------------------------
  void assert_unsigned_at(size_t n, const vindex& j, uint64_t u,
                          const decode ds[/*n*/]) const {
    // only small u for now
    proofs::check(u < 24, "u < 24");

    size_t expected = (0 << 5) + u;
    assert_atom_at(n, j, l_.konst(expected), ds);
  }

  //------------------------------------------------------------
  // "J is a header containing negative U."  (U >= 0, and
  // CBOR distinguishes 0 from -0 apparently)
  //------------------------------------------------------------
  void assert_negative_at(size_t n, const vindex& j, uint64_t u,
                          const decode ds[/*n*/]) const {
    // only small u for now
    proofs::check(u < 24, "u < 24");

    size_t expected = (1 << 5) + u;
    assert_atom_at(n, j, l_.konst(expected), ds);
  }

  //------------------------------------------------------------
  // "J is a header containing a boolean primitive (0xF4 or 0xF5)."
  //
  //------------------------------------------------------------
  void assert_bool_at(size_t n, const vindex& j, bool val,
                      const decode ds[/*n*/]) const {
    size_t expected = (7 << 5) + (val ? 21 : 20);
    assert_atom_at(n, j, l_.konst(expected), ds);
  }

  // Helps assemble the checks for date assertions.
  void date_helper(size_t n, const vindex& j, const decode ds[/*n*/],
                   std::vector<v8>& B /* size 22 */) const {
    const Logic& L = l_;  // shorthand
    const Routing<Logic> R(L);
    assert_header(n, j, ds);

    std::vector<v8> A(n);
    for (size_t i = 0; i < n; ++i) {
      A[i] = ds[i].as_bits;
    }

    const v8 defaultA =
        L.template vbit<8>(0);  // a constant that cannot appear in A[]
    R.shift(j, 20 + 2, B.data(), n, A.data(), defaultA, /*unroll=*/3);

    // Check for tag: date/time string.
    L.vassert_eq(&B[0], L.template vbit<8>(0xc0));

    // Check for string(20)
    L.vassert_eq(&B[1], L.template vbit<8>(0x74));
  }

  //------------------------------------------------------------
  // "J is a header containing date d < now."  now is 20 bytes
  // in the format 2023-11-01T09:00:00Z
  //------------------------------------------------------------
  void assert_date_before_at(size_t n, const vindex& j, const v8 now[/* 20 */],
                             const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand
    const Memcmp<Logic> CMP(L);
    std::vector<v8> B(20 + 2);
    date_helper(n, j, ds, B);
    auto lt = CMP.lt(20, &B[2], now);
    L.assert1(lt);
  }

  //------------------------------------------------------------
  // "J is a header containing date d > now."  now is 20 bytes in the
  // format 2023-11-01T09:00:00Z
  // ------------------------------------------------------------
  void assert_date_after_at(size_t n, const vindex& j, const v8 now[/* 20 */],
                            const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand
    const Memcmp<Logic> CMP(L);
    std::vector<v8> B(20 + 2);
    date_helper(n, j, ds, B);
    auto lt = CMP.lt(20, &B[2], now);
    L.assert1(lt);
  }

  //------------------------------------------------------------
  // "J is a header containing represented by the byte EXPECTED in the
  // input."
  //------------------------------------------------------------
  void assert_atom_at(size_t n, const vindex& j, const EltW& expected,
                      const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand
    const Routing<Logic> R(L);

    assert_header(n, j, ds);

    std::vector<EltW> A(n);
    for (size_t i = 0; i < n; ++i) {
      A[i] = ds[i].as_field_element;
    }

    EltW B[1];
    size_t unroll = 3;
    R.shift(j, 1, B, n, A.data(), L.konst(256), unroll);
    L.assert_eq(&B[0], expected);
  }

  //------------------------------------------------------------
  // "J is a header beginning a byte array of length LEN that
  // is the big-endian representation of EltW X."
  // ------------------------------------------------------------
  void assert_elt_as_be_bytes_at(size_t n, const vindex& j, size_t len, EltW X,
                                 const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand
    const Routing<Logic> R(L);

    std::vector<EltW> A(n);
    for (size_t i = 0; i < n; ++i) {
      A[i] = ds[i].as_field_element;
    }
    EltW tx = L.konst(0), k256 = L.konst(256);

    std::vector<EltW> B(2 + len);
    size_t unroll = 3;
    size_t si = 1;
    R.shift(j, len + 2, B.data(), n, A.data(), L.konst(0), unroll);
    if (len < 24) {
      size_t expected_header = (2 << 5) + len;
      auto eh = L.konst(expected_header);
      L.assert_eq(&B[0], eh);
    } else if (len < 256) {
      size_t expected_header = (2 << 5) + 24;
      auto eh = L.konst(expected_header);
      L.assert_eq(&B[0], eh);
      L.assert_eq(&B[1], L.konst(len));
      si = 2;
    } else {
      check(false, "len >= 256");
    }

    for (size_t i = 0; i < len; ++i) {
      auto tmp = L.mul(&tx, k256);
      tx = L.add(&tmp, B[i + si]);
    }

    L.assert_eq(&tx, X);
  }

  //------------------------------------------------------------
  // "Position j contains a header"
  //------------------------------------------------------------
  void assert_header(size_t n, const vindex& j, const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand

    L.vassert_is_bit(j);

    // giant dot product since the veq(j, .) terms are mutually exclusive.
    auto f = [&](size_t i) { return L.land(&ds[i].header, L.veq(j, i)); };
    L.assert1(L.lor_exclusive(0, n, f));
  }

  //------------------------------------------------------------
  // "A map starts at position j"
  //------------------------------------------------------------
  void assert_map_header(size_t n, const vindex& j,
                         const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand

    L.vassert_is_bit(j);

    // giant dot product since the veq(j, .) terms are mutually exclusive.
    auto f = [&](size_t i) {
      auto eq_ji = L.veq(j, i);
      auto dsi = L.land(&ds[i].mapp, ds[i].header);
      return L.land(&eq_ji, dsi);
    };
    L.assert1(L.lor_exclusive(0, n, f));
  }

  //------------------------------------------------------------
  // "Position M starts a map of level LEVEL.  (K, V) are headers
  // representing the J-th pair in that map"
  //------------------------------------------------------------
  void assert_map_entry(size_t n, const vindex& m, size_t level,
                        const vindex& k, const vindex& v, const vindex& j,
                        const decode ds[/*n*/],
                        const parse_output ps[/*n*/]) const {
    const Logic& L = l_;  // shorthand
    const Routing<Logic> R(L);

    assert_map_header(n, m, ds);
    assert_header(n, k, ds);
    assert_header(n, v, ds);

    for (size_t l = 0; l < kNCounters; ++l) {
      std::vector<EltW> A(n);
      for (size_t i = 0; i < n; ++i) {
        A[i] = ps[i].c[l];
      }

      // Select counters[m], counters[k], and counters[v].
      EltW cm, ck, cv;

      const size_t unroll = 3;
      R.shift(m, 1, &cm, n, A.data(), L.konst(0), unroll);
      R.shift(k, 1, &ck, n, A.data(), L.konst(0), unroll);
      R.shift(v, 1, &cv, n, A.data(), L.konst(0), unroll);

      if (l <= level) {
        // Counters[L] must agree at the key, value, and root
        // of the map.
        L.assert_eq(&cm, ck);
        L.assert_eq(&cm, cv);
      } else if (l == level + 1) {
        auto one = L.konst(1);
        auto two = L.konst(2);
        // LEVEL+1 counters must have the right number of decrements.
        // Specifically, if the counter at the map is N, then the j-th
        // key has N-(2*j+1) and the j-th value has N-(2*j+2)
        auto twoj = L.mul(&two, ba_index_.as_field_element(j));
        L.assert_eq(&cm, L.add(&ck, L.add(&twoj, one)));
        L.assert_eq(&cm, L.add(&cv, L.add(&twoj, two)));
      } else {
        // not sure if this is necessary, but all other counters
        // of CM are supposed to be zero.
        L.assert0(cm);
      }
    }
  }

  //------------------------------------------------------------
  // "JROOT is the first byte of the actual (unpadded) input and
  // all previous bytes are 0"
  //------------------------------------------------------------
  void assert_input_starts_at(size_t n, const vindex& jroot,
                              const vindex& input_len,
                              const decode ds[/*n*/]) const {
    const Logic& L = l_;  // shorthand

    L.assert1(L.vleq(input_len, n));
    L.assert1(L.vlt(jroot, n));
    auto tot = L.vadd(jroot, input_len);
    L.vassert_eq(tot, n);

    for (size_t i = 0; i < n; ++i) {
      L.assert0(L.lmul(&ds[i].as_field_element, L.vlt(i, jroot)));
    }
  }

  //------------------------------------------------------------
  // Utilities
  //------------------------------------------------------------
  // The circuit accepts up to N input positions, of which
  // INPUT_LEN are actual input and the rest are ignored.
  void decode_all(size_t n, decode ds[/*n*/], const v8 in[/*n*/],
                  const position_witness pw[/*n*/]) const {
    for (size_t i = 0; i < n; ++i) {
      ds[i] = decode_one_v8(in[i]);
      ds[i].header = bp_.pluckb(pw[i].encoded_sel_header);
    }
  }

  void decode_and_assert_decode(size_t n, decode ds[/*n*/], const v8 in[/*n*/],
                                const position_witness pw[/*n*/],
                                const global_witness& gw) const {
    decode_all(n, ds, in, pw);
    assert_decode(n, ds, pw, gw);
  }

  void decode_and_assert_decode_and_parse(size_t n, decode ds[/*n*/],
                                          parse_output ps[/*n*/],
                                          const v8 in[/*n*/],
                                          const position_witness pw[/*n*/],
                                          const global_witness& gw) const {
    decode_and_assert_decode(n, ds, in, pw, gw);
    parse(n, ps, ds, pw, gw);
    assert_parse(n, ds, ps, gw);
  }

 private:
  const Logic& l_;
  const BitAdder<Logic, 5> ba_count_;
  const BitAdder<Logic, 8> ba_byte_;
  const BitAdder<Logic, kIndexBits> ba_index_;
  const CborPlucker<Logic, kNCounters> bp_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_CBOR_H_
