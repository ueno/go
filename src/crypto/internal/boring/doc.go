// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package boring provides access to BoringCrypto implementation functions.
// Check the constant Enabled to find out whether BoringCrypto is available.
// If BoringCrypto is not available, the functions in this package all panic.
package boring

import "github.com/golang-fips/openssl/v2"

// A BigInt is the raw words from a BigInt.
// This definition allows us to avoid importing math/big.
// Conversion between BigInt and *big.Int is in crypto/internal/boring/bbig.
type BigInt = openssl.BigInt

