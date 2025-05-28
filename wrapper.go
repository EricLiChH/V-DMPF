package vdpf

// Testing in C the time goes from 7 to 4 seconds for 1000000 with the O3 flag
// Since cgo removes all optimization flags we first compile a (optimized)
// static library and then link it.
// Simon Langowski spent many hours debugging this.

// #cgo CFLAGS: -I${SRCDIR}/include
// #cgo LDFLAGS: ${SRCDIR}/src/libdpf.a -lcrypto -lssl -lm
// #include "dpf.h"
// #include "mmo.h"
// #include "vdpf.h"
import "C"
import (
	"unsafe"
)

var HASH1BLOCKOUT uint = 4
var HASH2BLOCKOUT uint = 2

type PrfCtx *C.struct_evp_cipher_ctx_st
type Hash *C.struct_Hash

func NewDPFKey(bytes []byte, dataSize uint, rangeSize uint) *DPFKey {
	return &DPFKey{bytes, dataSize, rangeSize}
}

func InitDPFContext(prfKey []byte) PrfCtx {
	if len(prfKey) != 16 {
		panic("bad prf key size")
	}

	p := C.getDPFContext((*C.uint8_t)(unsafe.Pointer(&prfKey[0])))
	return p
}

func InitVDPFContext(prfKey []byte) PrfCtx {

	p := InitDPFContext(prfKey)

	return p
}

func DestroyDPFContext(ctx PrfCtx) {
	C.destroyContext(ctx)
}

func DestroyMMOHash(hash Hash) {
	C.destroyMMOHash(hash)
}

func (dpf *Dpf) GenDPFKeys(specialIndex uint64, rangeSize uint, dataSize uint, data []byte) (*DPFKey, *DPFKey) {
	if len(data) != int(dataSize) {
		panic("invalid data size")
	}
	keySize := dpf.RequiredKeySize(dataSize, rangeSize)
	k0 := make([]byte, keySize)
	k1 := make([]byte, keySize)

	C.genDPF(
		dpf.ctx,
		C.int(rangeSize),
		C.uint64_t(specialIndex),
		C.int(dataSize),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		(*C.uint8_t)(unsafe.Pointer(&k0[0])),
		(*C.uint8_t)(unsafe.Pointer(&k1[0])),
	)

	return NewDPFKey(k0, dataSize, rangeSize), NewDPFKey(k1, dataSize, rangeSize)
}

func (vdpf *Vdpf) GenVDPFKeys(specialIndex uint64, rangeSize uint, dataSize uint, data []byte) (*DPFKey, *DPFKey) {
	if len(data) != int(dataSize) {
		panic("invalid data size")
	}
	keySize := vdpf.RequiredKeySize(dataSize, rangeSize)
	k0 := make([]byte, keySize)
	k1 := make([]byte, keySize)
	h1 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H1Key)), C.uint64_t(HASH1BLOCKOUT))
	defer C.destroyMMOHash(h1)
	C.genVDPF(
		vdpf.ctx,
		h1,
		C.int(rangeSize),
		C.uint64_t(specialIndex),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.int(dataSize),
		(*C.uint8_t)(unsafe.Pointer(&k0[0])),
		(*C.uint8_t)(unsafe.Pointer(&k1[0])),
	)

	return NewDPFKey(k0, dataSize, rangeSize), NewDPFKey(k1, dataSize, rangeSize)
}

func (dpf *Dpf) EvalDPF(key *DPFKey, index uint64) []byte {

	keySize := dpf.RequiredKeySize(key.DataSize, key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	res := make([]byte, key.DataSize)

	C.evalDPF(
		dpf.ctx,
		(*C.uint8_t)(unsafe.Pointer(&key.Bytes[0])),
		C.uint64_t(index),
		C.int(key.DataSize),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
	)

	return res
}

func (vdpf *Vdpf) EvalVDPF(key *DPFKey, index uint64) ([]byte, []byte) {

	keySize := vdpf.RequiredKeySize(key.DataSize, key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	res := make([]byte, key.DataSize)
	proof := make([]byte, 16*HASH2BLOCKOUT)
	h1 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H1Key)), C.uint64_t(HASH1BLOCKOUT))
	h2 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H2Key)), C.uint64_t(HASH2BLOCKOUT))
	defer C.destroyMMOHash(h1)
	defer C.destroyMMOHash(h2)
	C.evalVDPF(
		vdpf.ctx,
		h1,
		h2,
		C.int(key.DataSize),
		(*C.uint8_t)(unsafe.Pointer(&key.Bytes[0])),
		C.uint64_t(index),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])),
	)

	return res, proof
}

func (vdpf *Vdpf) BatchVerEval(key *DPFKey, indices []uint64) ([]byte, []byte) {

	keySize := vdpf.RequiredKeySize(key.DataSize, key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	pi := make([]byte, 16*HASH2BLOCKOUT)
	// in C: uint8_t **out
	out := make([]byte, int(key.DataSize)*len(indices))
	h1 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H1Key)), C.uint64_t(HASH1BLOCKOUT))
	h2 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H2Key)), C.uint64_t(HASH2BLOCKOUT))
	defer C.destroyMMOHash(h1)
	defer C.destroyMMOHash(h2)
	C.batchEvalVDPF(
		vdpf.ctx,
		h1,
		h2,
		C.int(key.DataSize),
		(*C.uint8_t)(unsafe.Pointer(&key.Bytes[0])),
		(*C.uint64_t)(unsafe.Pointer(&indices[0])),
		C.uint64_t(len(indices)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&pi[0])),
	)

	return out, pi
}

func (dpf *Dpf) FullDomainEval(key *DPFKey) []byte {

	if key.RangeSize > 32 {
		panic("range size is too big for full domain evaluation")
	}

	keySize := dpf.RequiredKeySize(key.DataSize, key.RangeSize)

	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	// extern void batchEvalDPF(EVP_CIPHER_CTX *ctx, int size, bool b, unsigned char* k, uint64_t *in, size_t inl, uint64_t* out);

	resSize := 1 << key.RangeSize

	res := make([]byte, int(key.DataSize)*resSize)

	C.fullDomainDPF(
		dpf.ctx,
		C.int(key.RangeSize),
		(*C.uint8_t)(unsafe.Pointer(&key.Bytes[0])),
		C.int(key.DataSize),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
	)

	return res

}

func (vdpf *Vdpf) FullDomainVerEval(key *DPFKey) ([]byte, []byte) {
	if key.RangeSize > 32 {
		panic("range size is too big for full domain evaluation")
	}

	keySize := vdpf.RequiredKeySize(key.DataSize, key.RangeSize)
	if len(key.Bytes) != int(keySize) {
		panic("invalid key size")
	}

	resSize := 1 << key.RangeSize
	pi := make([]byte, 16*HASH2BLOCKOUT)
	res := make([]byte, int(key.DataSize)*resSize)

	// 重新初始化哈希实例
	h1 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H1Key)), C.uint64_t(HASH1BLOCKOUT))
	h2 := C.initMMOHash((*C.uint8_t)(unsafe.Pointer(&vdpf.H2Key)), C.uint64_t(HASH2BLOCKOUT))
	defer C.destroyMMOHash(h1)
	defer C.destroyMMOHash(h2)

	C.fullDomainVDPF(
		vdpf.ctx,
		h1,
		h2,
		C.int(key.DataSize),
		(*C.uint8_t)(unsafe.Pointer(&key.Bytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&res[0])),
		(*C.uint8_t)(unsafe.Pointer(&pi[0])),
	)

	return res, pi
}
