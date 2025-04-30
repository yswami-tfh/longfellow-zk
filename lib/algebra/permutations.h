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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_PERMUTATIONS_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_PERMUTATIONS_H_

// cache-oblivious transpose
#include <stddef.h>

namespace proofs {

/*
The permutation class holds routines that apply a family of permutations to
arrays of Elt, including an efficient cache-oblivious transpose of a 2-d array.
The methods are organized in one class because of the template on Elt.
*/
template <class Elt>
class Permutations {
 public:
  static void swap(Elt* A, Elt* B) {
    Elt tmp = *A;
    *A = *B;
    *B = tmp;
  }

  static void transpose(Elt A[/*n*/], size_t lda, size_t n) {
    if (n <= kTransposeBasecase) {
      for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
          swap(&A[i * lda + j], &A[j * lda + i]);
        }
      }
    } else {
      transpose(A, lda, n / 2);
      transpose_and_swap(A + n / 2, A + lda * (n / 2), lda, n / 2);
      transpose(A + (lda + 1) * (n / 2), lda, n / 2);
    }
  }

  static void bitrev(Elt A[/*n*/], size_t n) {
    size_t revi = 0;
    for (size_t i = 0; i < n - 1; ++i) {
      if (i < revi) {
        swap(&A[i], &A[revi]);
      }

      bitrev_increment(&revi, n);
    }
  }

  // reverse x[i,j)
  static void reverse(Elt* x, size_t i, size_t j) {
    while (i + 1 < j) {
      --j;
      swap(&x[i], &x[j]);
      i++;
    }
  }

  /* X[i] = X[(i+shift) mod N] */
  /* We now use the notation X{N} to denote that X consists of N
     elements.  We have X = [A{SHIFT} B{N-SHIFT}].  We want
     X' = [B A] = rev[rev(A) rev(B)], where rev(A) reverses
     array A in-place.
  */

  static void rotate(Elt x[/*n*/], size_t n, size_t shift) {
    if (shift > 0) {
      reverse(x, 0, shift);
      reverse(x, shift, n);
      reverse(x, 0, n);
    }
  }

  static void unrotate(Elt x[/*n*/], size_t n, size_t shift) {
    if (shift > 0) {
      reverse(x, 0, n);
      reverse(x, shift, n);
      reverse(x, 0, shift);
    }
  }

 private:
  static constexpr size_t kTransposeBasecase = 8;

  static void bitrev_increment(size_t* j, size_t bit) {
    do {
      bit >>= 1;
      *j ^= bit;
    } while (!(*j & bit));
  }

  static void transpose_and_swap(Elt* A, Elt* B, size_t lda, size_t n) {
    if (n <= kTransposeBasecase) {
      for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
          swap(&A[i * lda + j], &B[j * lda + i]);
        }
      }
    } else {
      transpose_and_swap(A, B, lda, n / 2);
      transpose_and_swap(A + n / 2, B + lda * (n / 2), lda, n / 2);
      transpose_and_swap(A + lda * (n / 2), B + (n / 2), lda, n / 2);
      transpose_and_swap(A + (lda + 1) * (n / 2), B + (lda + 1) * (n / 2), lda,
                         n / 2);
    }
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_PERMUTATIONS_H_
