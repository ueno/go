//go:build !goexperiment.strictfipsruntime
// +build !goexperiment.strictfipsruntime

package backend

var isStrictFIPS bool = false

func strictFIPSOpenSSLRuntimeCheck() {
}

func strictFIPSNonCompliantBinaryCheck() {
}
