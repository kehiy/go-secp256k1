//go:build libsecp256k1

package gosecp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/libsecp256k1/include -I${SRCDIR}/libsecp256k1/src
#cgo CFLAGS: -DECMULT_GEN_PREC_BITS=4
#cgo CFLAGS: -DECMULT_WINDOW_SIZE=15
#cgo CFLAGS: -DENABLE_MODULE_SCHNORRSIG=1
#cgo CFLAGS: -DENABLE_MODULE_EXTRAKEYS=1

#include "./libsecp256k1/include/secp256k1_extrakeys.h"
#include "./libsecp256k1/include/secp256k1_schnorrsig.h"
#include "./libsecp256k1/include/secp256k1.h"
*/
import "C"
import "unsafe"

type Schnorrsig struct {
	Data [64]byte
}

func (xop *XonlyPubkey) SchnorrsigVerify(context *C.secp256k1_context, sig *Schnorrsig, msg []byte) bool {
	var xonly C.secp256k1_xonly_pubkey
	copy((*[64]byte)(unsafe.Pointer(&xonly.data[0]))[:], xop.Data[:])

	return C.secp256k1_schnorrsig_verify(
        context,
        (*C.uchar)(unsafe.Pointer(&sig.Data[0])),
        (*C.uchar)(unsafe.Pointer(&msg[0])),
        C.size_t(len(msg)),
        &xonly,
    ) == 1
}
