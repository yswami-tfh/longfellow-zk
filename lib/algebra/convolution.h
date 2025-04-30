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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CONVOLUTION_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CONVOLUTION_H_

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/blas.h"
#include "algebra/fft.h"
#include "util/panic.h"

/*
All of the classes in this package compute convolutions.
That is, given inputs arrays of field elements x, y, with |x|=n, |y|=m,
these methods compute the first m entries of 

   z[k] = \sum_{i=0}^{n-1} x[i] y[k-i]

SlowConvolution uses an O(n*m) method for testing validation.

FFTConvolution and FFTExtConvolution first pad y to length n and use advanced
FFT algorithms to compute the same in O(nlogn) time.

The const Field& objects that are passed have lifetimes that exceed the call
durations and can be safely passed by const reference.
*/

namespace proofs {

// Returns the smallest power of 2 that is at least n.
static size_t choose_padding(const size_t n) {
  size_t p = 1;
  while (p < n) {
    p *= 2;
  }
  return p;
}

template <class Field>
class FFTConvolution {
  using Elt = typename Field::Elt;

 public:
  FFTConvolution(size_t n, size_t m, const Field& f, const Elt omega,
                  uint64_t omega_order, const Elt y[/*m*/])
      : f_(f),
        omega_(omega),
        omega_order_(omega_order),
        n_(n),
        m_(m),
        padding_(choose_padding(m)),
        y_fft_(padding_, f_.zero()) {
    // First copy/pad y.
    Blas<Field>::copy(m, &y_fft_[0], 1, y, 1);
    // take fft of y_fft_
    FFT<Field>::fft(&y_fft_[0], padding_, omega_, omega_order_, f_);
    // To compute the inverse fft, we must divide by the padding
    Elt inverse_padding = f_.invertf(f_.of_scalar(padding_));
    for (size_t i = 0; i < padding_; ++i) {
      f_.mul(y_fft_[i], inverse_padding);
    }
  }

  // Computes (first m entries of) convolution of x with y, outputs in z:
  // z[k] = \sum_{i=0}^{n-1} x[i] y[k-i].
  // Note that y has already been FFT'd and divided by padding_ in constructor
  void convolution(const Elt x[/*n_*/], Elt z[/*m_*/]) const {
    std::vector<Elt> x_fft(padding_, f_.zero());
    // Blas<Field>::clear(padding_, &x_fft[0], 1, f_);
    Blas<Field>::copy(n_, &x_fft[0], 1, x, 1);
    FFT<Field>::fft(&x_fft[0], padding_, omega_, omega_order_, f_);
    // Multiply FFTs together.
    for (size_t i = 0; i < padding_; ++i) {
      f_.mul(x_fft[i], y_fft_[i]);
    }
    // Take inverse fft.
    FFT<Field>::fft(&x_fft[0], padding_, f_.invertf(omega_), omega_order_, f_);
    Blas<Field>::copy(m_, z, 1, &x_fft[0], 1);
  }

 private:
  const Field& f_;
  const Elt omega_;
  const uint64_t omega_order_;

  // n is the number of points input
  size_t n_;
  size_t m_;  // total number of points output (points in + new points out)
  size_t padding_;

  // fft(y[i]) / padding
  // padded with zeroes to the next power of 2 at least m.
  std::vector<Elt> y_fft_;
};

template <class Field>
class FFTConvolutionFactory {
  using Elt = typename Field::Elt;

 public:
  using Convolver = FFTConvolution<Field>;
  FFTConvolutionFactory(const Field& f, const Elt omega, uint64_t omega_order)
      : f_(f), omega_(omega), omega_order_(omega_order) {}

  std::unique_ptr<const Convolver> make(size_t n, size_t m,
                                        const Elt y[/*m*/]) const {
    return std::make_unique<const Convolver>(n, m, f_, omega_, omega_order_, y);
  }

 private:
  const Field& f_;
  const Elt omega_;
  const uint64_t omega_order_;
};

template <class Field, class FieldExt>
class FFTExtConvolution {
  using Elt = typename Field::Elt;
  using EltExt = typename FieldExt::Elt;

 public:
  FFTExtConvolution(size_t n, size_t m, const Field& f,
                      const FieldExt& f_ext, const EltExt omega,
                      uint64_t omega_order, const Elt y[/*m*/])
      : f_(f),
        f_ext_(f_ext),
        omega_(omega),
        omega_order_(omega_order),
        n_(n),
        m_(m),
        padding_(choose_padding(m)),
        y_fft_(padding_, f_ext_.zero()) {
    // First pad y
    for (size_t i = 0; i < m; ++i) {
      y_fft_[i] = f_ext_.of_scalar(y[i]);
    }
    // take fft of inverses
    FFT<FieldExt>::fft(&y_fft_[0], padding_, omega_, omega_order_, f_ext_);
    // To compute the inverse fft, we must divide by the padding
    EltExt inverse_padding = f_ext_.invertf(f_ext_.of_scalar(padding_));
    for (size_t i = 0; i < padding_; ++i) {
      f_ext_.mul(y_fft_[i], inverse_padding);
    }
  }

  // Computes (first m entries of) convolution of x with y, stores in z:
  // z[k] = \sum_{i=0}^{n-1} x[i] y[k-i].
  // Note that y has already been FFT'd and divided by padding_ in constructor
  void convolution(const Elt x[/*n_*/], Elt z[/*m_*/]) const {
    std::vector<EltExt> x_ext_fft(padding_, f_ext_.zero());
    for (size_t i = 0; i < n_; ++i) {
      x_ext_fft[i] = f_ext_.of_scalar(x[i]);
    }
    FFT<FieldExt>::fft(&x_ext_fft[0], padding_, omega_, omega_order_, f_ext_);
    // Multiply FFTs together.
    for (size_t i = 0; i < padding_; ++i) {
      f_ext_.mul(x_ext_fft[i], y_fft_[i]);
    }
    // Take inverse fft.
    FFT<FieldExt>::fft(&x_ext_fft[0], padding_, f_ext_.invertf(omega_),
                        omega_order_, f_ext_);
    for (size_t i = 0; i < m_; ++i) {
      check(f_ext_.is_real(x_ext_fft[i]),
            "non-zero complex component after FFT");
      z[i] = f_ext_.real(x_ext_fft[i]);
    }
  }

 private:
  const Field& f_;
  const FieldExt& f_ext_;
  const EltExt omega_;
  const uint64_t omega_order_;

  // n is the number of points input in x
  size_t n_;
  size_t m_;  // total number of points output in convolution
  size_t padding_;

  // fft(y[i]) / padding
  // padded with zeroes to the next power of 2 at least m.
  std::vector<EltExt> y_fft_;
};

template <class Field, class FieldExt>
class FFTExtConvolutionFactory {
  using Elt = typename Field::Elt;
  using EltExt = typename FieldExt::Elt;

 public:
  using Convolver = FFTExtConvolution<Field, FieldExt>;

  FFTExtConvolutionFactory(const Field& f, const FieldExt& f_ext,
                              const EltExt omega, uint64_t omega_order)
      : f_(f), f_ext_(f_ext), omega_(omega), omega_order_(omega_order) {}

  std::unique_ptr<const Convolver> make(size_t n, size_t m,
                                        const Elt y[/*m*/]) const {
    return std::make_unique<const Convolver>(n, m, f_, f_ext_, omega_,
                                             omega_order_, y);
  }

 private:
  const Field& f_;
  const FieldExt& f_ext_;
  const EltExt omega_;
  const uint64_t omega_order_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_CONVOLUTION_H_
