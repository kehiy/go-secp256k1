//go:build libsecp256k1

package gosecp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/libsecp256k1/include -I${SRCDIR}/libsecp256k1/src
#cgo CFLAGS: -DECMULT_GEN_PREC_BITS=4
#cgo CFLAGS: -DECMULT_WINDOW_SIZE=15
#cgo CFLAGS: -DENABLE_MODULE_SCHNORRSIG=1
#cgo CFLAGS: -DENABLE_MODULE_EXTRAKEYS=1

#include "./libsecp256k1/include/secp256k1.h"
*/
import "C"

type Secp256k1Context struct {
	Flags uint
}

// todo:::
