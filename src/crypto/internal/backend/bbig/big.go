// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a mirror of
// https://github.com/golang/go/blob/36b87f273cc43e21685179dc1664ebb5493d26ae/src/crypto/internal/boring/bbig/big.go.

package bbig

import (
       "github.com/golang-fips/openssl/v2/bbig"
)

var Enc = bbig.Enc
var Dec = bbig.Dec
