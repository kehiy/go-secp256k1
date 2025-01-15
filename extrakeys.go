//go:build libsecp256k1

package gosecp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/libsecp256k1/include -I${SRCDIR}/libsecp256k1/src
#cgo CFLAGS: -DECMULT_GEN_PREC_BITS=4
#cgo CFLAGS: -DECMULT_WINDOW_SIZE=15
#cgo CFLAGS: -DENABLE_MODULE_SCHNORRSIG=1
#cgo CFLAGS: -DENABLE_MODULE_EXTRAKEYS=1

#include "./libsecp256k1/include/secp256k1_extrakeys.h"
#include "./libsecp256k1/include/secp256k1.h"
*/
import "C"
import "unsafe"

// todo::: use internal context.

type (
	XonlyPubkey struct {
		Data [64]byte
	}

	Pubkey struct {
		Data [64]byte
	}

	Seckey struct {
		Data [32]byte
	}

	Keypair struct {
		Data [96]byte
	}
)

func NewKeypairFromSeckey(context *C.secp256k1_context, seckey [32]byte) *Keypair {
	var keypair C.secp256k1_keypair
	kp := new(Keypair)

	if C.secp256k1_keypair_create(context, &keypair, (*C.uchar)(unsafe.Pointer(&seckey[0]))) == 1 {
		copy(kp.Data[:], (*[64]byte)(unsafe.Pointer(&keypair.data[0]))[:])
		return nil
	}

	return kp
}

func (kp *Keypair) Seckey(context *C.secp256k1_context) *Seckey {
	var seckey [32]byte
	var keypair C.secp256k1_keypair

	copy((*[96]byte)(unsafe.Pointer(&keypair.data[0]))[:], kp.Data[:])

	if C.secp256k1_keypair_sec(context, (*C.uchar)(unsafe.Pointer(&seckey[0])), &keypair) == 1 {
		return &Seckey{
			Data: seckey,
		}
	}

	return nil
}

func (kp *Keypair) Pubkey(context *C.secp256k1_context) *Pubkey {
	var pubkey C.secp256k1_pubkey
	var keypair C.secp256k1_keypair
	copy((*[96]byte)(unsafe.Pointer(&keypair.data[0]))[:], kp.Data[:])

	pk := new(Pubkey)

	if C.secp256k1_keypair_pub(context, &pubkey, &keypair) == 1 {
		copy((*[64]byte)(unsafe.Pointer(&pubkey.data[0]))[:], pk.Data[:])
		return pk
	}

	return nil
}

func (kp *Keypair) XonlyPubkey(context *C.secp256k1_context) *XonlyPubkey {
	var xonly C.secp256k1_xonly_pubkey
	var keypair C.secp256k1_keypair
	copy((*[96]byte)(unsafe.Pointer(&keypair.data[0]))[:], kp.Data[:])

	xopk := new(XonlyPubkey)

	// todo::: getting int *pk_parity from caller.
	if C.secp256k1_keypair_xonly_pub(context, &xonly, nil, &keypair) == 1 {
		copy((*[64]byte)(unsafe.Pointer(&xonly.data[0]))[:], xopk.Data[:])
		return xopk
	}

	return nil
}

func (xp *XonlyPubkey) XonlyPubkeyParse(context *C.secp256k1_context, pk [32]byte) bool {
	var xonly C.secp256k1_xonly_pubkey

	if C.secp256k1_xonly_pubkey_parse(context, &xonly, (*C.uchar)(unsafe.Pointer(&pk[0]))) == 1 {
		copy(xp.Data[:], (*[64]byte)(unsafe.Pointer(&xonly.data[0]))[:])
		return true
	}

	return false
}
