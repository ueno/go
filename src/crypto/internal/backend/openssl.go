// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && cgo && !android && !gocrypt && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,cgo,!android,!gocrypt,!cmd_go_bootstrap,!msan,!no_openssl

// Package openssl provides access to OpenSSLCrypto implementation functions.
// Check the variable Enabled to find out whether OpenSSLCrypto is available.
// If OpenSSLCrypto is not available, the functions in this package all panic.
package backend

import (
	"crypto/internal/boring/sig"
	"github.com/golang-fips/openssl/v2"
	"os"
	"syscall"
)

// Enabled controls whether FIPS crypto is enabled.
var enabled bool

var knownVersions = [...]string{"3", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}

func init() {
	version, _ := syscall.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	if version == "" {
		var fallbackVersion string
		for _, v := range knownVersions {
			exists, fips := openssl.CheckVersion(v)
			if exists && fips {
				version = v
				break
			}
			if exists && fallbackVersion == "" {
				fallbackVersion = v
			}
		}
		if version == "" && fallbackVersion != "" {
			version = fallbackVersion
		}
	}
	if err := openssl.Init(version); err != nil {
		panic("opensslcrypto: can't initialize OpenSSL " + version + ": " + err.Error())
	}
	// 0: FIPS opt-out: abort the process if it is enabled and can't be disabled.
	// 1: FIPS required: abort the process if it is not enabled and can't be enabled.
	// other values: do not override OpenSSL configured FIPS mode.
	var fips string
	if v, ok := syscall.Getenv("GOLANG_FIPS"); ok {
		fips = v
	} else if hostFIPSModeEnabled() {
		// System configuration can only force FIPS mode.
		fips = "1"
	}
	switch fips {
	case "0":
		if openssl.FIPS() {
			if err := openssl.SetFIPS(false); err != nil {
				panic("opensslcrypto: can't disable FIPS mode for " + openssl.VersionText() + ": " + err.Error())
			}
		}
	case "1":
		if !openssl.FIPS() {
			if err := openssl.SetFIPS(true); err != nil {
				panic("opensslcrypto: can't enable FIPS mode for " + openssl.VersionText() + ": " + err.Error())
			}
		}
		enabled = true
	}
	sig.BoringCrypto()
}

func Enabled() bool {
	return enabled
}

// Unreachable marks code that should be unreachable
// when OpenSSLCrypto is in use. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if Enabled() {
		panic("opensslcrypto: invalid code execution")
	}
}

// ExecutingTest returns a boolean indicating if we're
// executing under a test binary or not.
func ExecutingTest() bool {
	name := os.Args[0]
	return hasSuffix(name, "_test") || hasSuffix(name, ".test")
}

// Provided by runtime.crypto_backend_runtime_arg0 to avoid os import.
func runtime_arg0() string

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

// UnreachableExceptTests marks code that should be unreachable
// when OpenSSLCrypto is in use. It panics.
func UnreachableExceptTests() {
	name := runtime_arg0()
	// If OpenSSLCrypto ran on Windows we'd need to allow _test.exe and .test.exe as well.
	if Enabled() && !hasSuffix(name, "_test") && !hasSuffix(name, ".test") {
		println("opensslcrypto: unexpected code execution in", name)
		panic("opensslcrypto: invalid code execution")
	}
}

const RandReader = openssl.RandReader

var NewGCMTLS = openssl.NewGCMTLS
var NewSHA1 = openssl.NewSHA1
var NewSHA224 = openssl.NewSHA224
var NewSHA256 = openssl.NewSHA256
var NewSHA384 = openssl.NewSHA384
var NewSHA512 = openssl.NewSHA512

var SHA1 = openssl.SHA1
var SHA224 = openssl.SHA224
var SHA256 = openssl.SHA256
var SHA384 = openssl.SHA384
var SHA512 = openssl.SHA512

var NewHMAC = openssl.NewHMAC

var NewAESCipher = openssl.NewAESCipher

type PublicKeyECDSA = openssl.PublicKeyECDSA
type PrivateKeyECDSA = openssl.PrivateKeyECDSA

var GenerateKeyECDSA = openssl.GenerateKeyECDSA
var NewPrivateKeyECDSA = openssl.NewPrivateKeyECDSA
var NewPublicKeyECDSA = openssl.NewPublicKeyECDSA
var SignMarshalECDSA = openssl.SignMarshalECDSA
var VerifyECDSA = openssl.VerifyECDSA
var HashVerifyECDSA = openssl.HashVerifyECDSA
var HashSignECDSA = openssl.HashSignECDSA

type PublicKeyECDH = openssl.PublicKeyECDH
type PrivateKeyECDH = openssl.PrivateKeyECDH

var GenerateKeyECDH = openssl.GenerateKeyECDH
var NewPrivateKeyECDH = openssl.NewPrivateKeyECDH
var NewPublicKeyECDH = openssl.NewPublicKeyECDH
var ECDH = openssl.ECDH

type PublicKeyRSA = openssl.PublicKeyRSA
type PrivateKeyRSA = openssl.PrivateKeyRSA

var DecryptRSAOAEP = openssl.DecryptRSAOAEP
var DecryptRSAPKCS1 = openssl.DecryptRSAPKCS1
var DecryptRSANoPadding = openssl.DecryptRSANoPadding
var EncryptRSAOAEP = openssl.EncryptRSAOAEP
var EncryptRSAPKCS1 = openssl.EncryptRSAPKCS1
var EncryptRSANoPadding = openssl.EncryptRSANoPadding
var GenerateKeyRSA = openssl.GenerateKeyRSA
var NewPrivateKeyRSA = openssl.NewPrivateKeyRSA
var NewPublicKeyRSA = openssl.NewPublicKeyRSA
var SignRSAPKCS1v15 = openssl.SignRSAPKCS1v15
var SignRSAPSS = openssl.SignRSAPSS
var VerifyRSAPKCS1v15 = openssl.VerifyRSAPKCS1v15
var VerifyRSAPSS = openssl.VerifyRSAPSS

var ExtractHKDF = openssl.ExtractHKDF
var ExpandHKDF = openssl.ExpandHKDF
var SupportsHKDF = openssl.SupportsHKDF
