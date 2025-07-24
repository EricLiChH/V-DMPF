package vdmpf

import (
	"crypto/rand"
)

type PrfKey [16]byte
type HashKey [16]byte

type DPFKey struct {
	Bytes     []byte
	DataSize  uint
	RangeSize uint
}

type DMPFKey struct {
	Bytes      []byte
	DataSize   uint
	RangeSize  uint
	RangePoint uint
}

type CompressedDMPFKey struct {
	Bytes      []byte
	DataSize   uint
	RangeSize  uint
	RangePoint uint
}

type Dpf struct {
	PrfKey PrfKey
	ctx    PrfCtx
}

type Dmpf struct {
	prfKey PrfKey
	ctx    PrfCtx
}

type Vdpf struct {
	Dpf
	H1Key HashKey
	H2Key HashKey
}

type Vdmpf struct {
	Dmpf
	H1Key HashKey
	H2Key HashKey
}

func DPFInitialize(prfKey PrfKey) *Dpf {
	return &Dpf{prfKey, InitDPFContext(prfKey[:])}
}

func GenerateVDPFHashKeys() [2]HashKey {
	var hashKeys [2]HashKey

	_, err := rand.Read(hashKeys[0][:])
	if err != nil {
		panic("Error generating randomness")
	}
	_, err = rand.Read(hashKeys[1][:])
	if err != nil {
		panic("Error generating randomness")
	}

	return hashKeys
}

func GenerateVDMPFHashKeys() [2]HashKey {
	var hashKeys [2]HashKey
	_, err := rand.Read(hashKeys[0][:])
	if err != nil {
		panic("Error generating randomness")
	}
	_, err = rand.Read(hashKeys[1][:])
	if err != nil {
		panic("Error generating randomness")
	}

	return hashKeys
}

func GeneratePRFKey() PrfKey {
	randKey := PrfKey{}
	_, err := rand.Read(randKey[:])
	if err != nil {
		panic("Error generating randomness")
	}
	return randKey
}

func DMPFInitialize(prfKey PrfKey) *Dmpf {
	return &Dmpf{prfKey, InitDPFContext(prfKey[:])}
}

func VDPFInitialize(prfKey PrfKey, hashKeys [2]HashKey) *Vdpf {

	prfctx := InitVDPFContext(prfKey[:])
	return &Vdpf{Dpf{prfKey, prfctx}, hashKeys[0], hashKeys[1]}
}

func VDMPFInitialize(prfKey PrfKey, hashKeys [2]HashKey) *Vdmpf {
	prfctx := InitVDMPFContext(prfKey[:])
	return &Vdmpf{Dmpf{prfKey, prfctx}, hashKeys[0], hashKeys[1]}
}

func (dpf *Dpf) RequiredKeySize(dataSize uint, rangeSize uint) uint {
	return (18 * rangeSize) + 18 + dataSize
}

func (dpf *Dpf) Free() {
	DestroyDPFContext(dpf.ctx)
}

func (dmpf *Dmpf) RequiredKeySize(dataSize uint, rangeSize uint, rangePoint uint) uint {
	return (24 * rangeSize * rangePoint) + 19 + dataSize*rangePoint
}

func (dmpf *Dmpf) Free() {
	DestroyDPFContext(dmpf.ctx)
}

func (vdpf *Vdpf) RequiredKeySize(dataSize uint, rangeSize uint) uint {
	return (18 * rangeSize) + 18 + dataSize + 16*4
}

func (vdpf *Vdpf) Free() {
	DestroyDPFContext(vdpf.ctx)
}

func (vdmpf *Vdmpf) RequiredKeySize(dataSize uint, rangeSize uint, rangePoint uint) uint {
	return (19 + 24*rangeSize*rangePoint + dataSize*rangePoint + 16*4*rangePoint)
}

func (vdmpf *Vdmpf) Free() {
	DestroyDPFContext(vdmpf.ctx)
}
