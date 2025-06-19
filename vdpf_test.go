package vdpf

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"
)

const numTrials = 100

func TestCorrectPointFunctionTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := 1 << 4
		specialIndex := uint64(rand.Intn(num))

		prfKey := GeneratePRFKey()

		// generate fss Keys on client
		client := DPFInitialize(prfKey)

		// fmt.Printf("index  %v\n", specialIndex)
		data := make([]byte, 16)
		for i := range data {
			data[i] = byte(rand.Intn(256))
		}
		dataSize := len(data)
		keyA, keyB := client.GenDPFKeys(specialIndex, 4, uint(dataSize), data)

		// simulate the server
		server := DPFInitialize(client.PrfKey)

		// 测试specialIndex
		ans0 := server.EvalDPF(keyA, specialIndex)
		ans1 := server.EvalDPF(keyB, specialIndex)

		for i := 0; i < dataSize; i++ {
			ans := ans0[i] ^ ans1[i]
			if ans != data[i] {
				t.Fatalf("Trial %v: At specialIndex %v, position %v: Expected: %v Got: %v",
					trial, specialIndex, i, data[i], ans)
			}
		}

		// 测试多个非specialIndex点
		for testIndex := uint64(0); testIndex < uint64(num); testIndex++ {
			if testIndex == specialIndex {
				continue
			}
			ans0 = server.EvalDPF(keyA, testIndex)
			ans1 = server.EvalDPF(keyB, testIndex)

			for i := 0; i < dataSize; i++ {
				ans := ans0[i] ^ ans1[i]
				if ans != 0 {
					t.Fatalf("Trial %v: At index %v, position %v: Expected: 0 Got: %v",
						trial, testIndex, i, ans)
				}
			}
		}
	}
}

func TestCorrectPointFunctionTwoServerFullDomain(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := 1 << 4
		specialIndex := uint64(rand.Intn(num))
		data := make([]byte, 10)
		for i := range data {
			data[i] = byte(rand.Intn(256))
		}

		prfKey := GeneratePRFKey()

		// generate fss Keys on client
		client := DPFInitialize(prfKey)

		// fmt.Printf("index  %v\n", specialIndex)
		keyA, keyB := client.GenDPFKeys(specialIndex, 4, 10, data)
		// fmt.Printf("keyA = %v\n", keyA)
		// fmt.Printf("keyB = %v\n", keyB)

		// simulate the server
		server := DPFInitialize(client.PrfKey)

		ans0 := server.FullDomainEval(keyA)
		ans1 := server.FullDomainEval(keyB)

		// fmt.Printf("ans0 = %v\n", ans0)
		// fmt.Printf("ans1 = %v\n", ans1)
		// test specialIndex
		for i := 0; i < 10; i++ {
			ans := ans0[int(specialIndex)*10+i] ^ ans1[int(specialIndex)*10+i]
			if ans != data[i] {
				t.Fatalf("Trial %v: At specialIndex %v, position %v: Expected: %v Got: %v",
					trial, specialIndex, i, data[i], ans)
			}
		}

		for testIndex := uint64(0); testIndex < uint64(num); testIndex++ {
			if testIndex == specialIndex {
				continue
			}
			for i := 0; i < 10; i++ {
				ans := ans0[int(testIndex)*10+i] ^ ans1[int(testIndex)*10+i]
				if ans != 0 {
					t.Fatalf("Trial %v: At index %v, position %v: Expected: 0 Got: %v",
						trial, testIndex, i, ans)
				}
			}
		}
	}
}

func TestCorrectVerifiablePointFunctionTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := 1 << 4
		specialIndex := uint64(1)

		hashKeys := GenerateVDPFHashKeys()
		prfKey := GeneratePRFKey()

		// simulate the server
		server := VDPFInitialize(prfKey, hashKeys)

		// generate fss Keys on client
		client := VDPFInitialize(prfKey, hashKeys)

		// fmt.Printf("index  %v\n", specialIndex)
		data := make([]byte, 10)
		for i := range data {
			data[i] = byte(rand.Intn(256))
		}
		keyA, keyB := client.GenVDPFKeys(specialIndex, 4, 10, data)

		// fmt.Printf("keyA = %v\n", keyA)
		// fmt.Printf("keyB = %v\n", keyB)

		indices := make([]uint64, num)
		for i := 0; i < num; i++ {
			indices[i] = uint64(rand.Intn(num))
		}
		ans0, pi0 := server.BatchVerEval(keyA, indices)
		ans1, pi1 := server.BatchVerEval(keyB, indices)

		if !bytes.Equal(pi0, pi1) {
			fmt.Println()
			t.Fatalf("pi0 =/= p1\n%v\n%v\n", pi0, pi1)
		}

		for i := 0; i < 1<<4; i++ {
			for j := 0; j < 10; j++ {
				if uint64(indices[i]) == specialIndex && ans0[i*10+j]^ans1[i*10+j] != data[j] {
					t.Fatalf("Expected: %v Got: %v", ans0[i*10+j], ans1[i*10+j])
				}
				if uint64(indices[i]) != specialIndex && ans0[i*10+j]^ans1[i*10+j] != 0 {
					t.Fatalf("Expected: %v Got: %v", ans0[i*10+j], ans1[i*10+j])
				}
			}
		}
	}
}

func TestCorrectVerifiablePointFunctionFullDomain(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {

		rangeSize := 4

		num := 1 << rangeSize
		specialIndex := uint64(rand.Intn(num))

		hashKeys := GenerateVDPFHashKeys()
		prfKey := GeneratePRFKey()

		// generate fss Keys on client
		client := VDPFInitialize(prfKey, hashKeys)

		// fmt.Printf("index  %v\n", specialIndex)
		data := make([]byte, 10)
		for i := range data {
			data[i] = byte(rand.Intn(256))
		}
		keyA, keyB := client.GenVDPFKeys(specialIndex, uint(rangeSize), uint(10), data)

		// fmt.Printf("keyA = %v\n", keyA)
		// fmt.Printf("keyB = %v\n", keyB)

		// simulate the server
		hashkeys := GenerateVDPFHashKeys()
		server := VDPFInitialize(prfKey, hashkeys)

		ans0, pi0 := server.FullDomainVerEval(keyA)
		ans1, pi1 := server.FullDomainVerEval(keyB)

		if !bytes.Equal(pi0, pi1) {
			fmt.Printf("Trial %v: Proofs don't match!\n", trial)
			fmt.Printf("pi0 length: %d, pi1 length: %d\n", len(pi0), len(pi1))
			fmt.Printf("pi0: %x\n", pi0)
			fmt.Printf("pi1: %x\n", pi1)
			t.Fatalf("pi0 =/= pi1")
		}

		// fmt.Printf("ans0 = %v\n", ans0)
		// fmt.Printf("ans1 = %v\n", ans1)
		for i := 0; i < num; i++ {
			for j := 0; j < 10; j++ {
				if uint64(i) == specialIndex && ans0[i*10+j]^ans1[i*10+j] != data[j] {
					t.Fatalf("Expected: %v Got: %v", ans0[i*10+j], ans1[i*10+j])
				}
				if uint64(i) != specialIndex && ans0[i*10+j]^ans1[i*10+j] != 0 {
					t.Fatalf("Expected: %v Got: %v", ans0[i*10+j], ans1[i*10+j])
				}
			}
		}
	}
}

func TestCorrectMultiPointFunctionTwoServer(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := 1 << 4
		// Generate unique random indices to ensure strictly ascending order
		usedIndices := make(map[uint64]bool)
		specialIndexes := make([]uint64, 0, 10)
		for len(specialIndexes) < 10 {
			idx := uint64(rand.Intn(num))
			if !usedIndices[idx] {
				usedIndices[idx] = true
				specialIndexes = append(specialIndexes, idx)
			}
		}
		// Sort specialIndexes in ascending order as required by the C++ implementation
		slices.Sort(specialIndexes)
		data := make([]byte, 10)
		for i := range data {
			data[i] = byte(rand.Intn(256))
		}

		prfKey := GeneratePRFKey()

		client := DMPFInitialize(prfKey)
		keyA, keyB := client.GenDMPFKeys(specialIndexes, 4, 10, 1, data)

		server := DMPFInitialize(prfKey)

		indices := make([]uint64, num)
		for i := 0; i < num; i++ {
			indices[i] = uint64(rand.Intn(num))
		}
		// sort indices
		slices.Sort(indices)

		// test specialIndexes
		for i := 0; i < 10; i++ {
			ans0 := server.EvalDMPF(keyA, specialIndexes[i])
			ans1 := server.EvalDMPF(keyB, specialIndexes[i])
			if ans0[0]^ans1[0] != data[i] {
				fmt.Printf("specialIndexes[i] = %v\n", specialIndexes[i])
				fmt.Printf("ans0 = %v\n", ans0)
				fmt.Printf("ans1 = %v\n", ans1)
				fmt.Printf("data = %v\n", data)
				t.Fatalf("Expected: %v Got: %v", ans0[0]^ans1[0], data[i])
			}
		}

		// test non-specialIndexes
		for i := 0; i < num; i++ {
			if slices.Contains(specialIndexes, uint64(i)) {
				continue
			}
			ans0 := server.EvalDMPF(keyA, uint64(i))
			ans1 := server.EvalDMPF(keyB, uint64(i))
			if ans0[0]^ans1[0] != 0 {
				fmt.Printf("indices[i] = %v\n", uint64(i))
				fmt.Printf("ans0 = %v\n", ans0)
				fmt.Printf("ans1 = %v\n", ans1)
				t.Fatalf("Expected: %v Got: %v", 0, ans0[0]^ans1[0])
			}
		}
	}
}

func TestCorrectMultiPointFunctionTwoServerFullDomain(t *testing.T) {

	for trial := 0; trial < numTrials; trial++ {
		num := 1 << 4
		// Generate unique random indices to ensure strictly ascending order
		usedIndices := make(map[uint64]bool)
		specialIndexes := make([]uint64, 0, 10)
		for len(specialIndexes) < 10 {
			idx := uint64(rand.Intn(num))
			if !usedIndices[idx] {
				usedIndices[idx] = true
				specialIndexes = append(specialIndexes, idx)
			}
		}
		// Sort specialIndexes in ascending order as required by the C++ implementation
		slices.Sort(specialIndexes)
		data := make([]byte, 10)
		for i := range data {
			data[i] = byte(specialIndexes[i])
		}
		prfKey := GeneratePRFKey()
		client := DMPFInitialize(prfKey)

		keyA, keyB := client.GenDMPFKeys(specialIndexes, 4, 10, 1, data)

		server := DMPFInitialize(prfKey)

		ans0 := server.FullDomainEval(keyA)
		ans1 := server.FullDomainEval(keyB)

		for i := 0; i < num; i++ {
			if slices.Contains(specialIndexes, uint64(i)) {
				// Find the position of i in specialIndexes array
				var dataIndex int
				for j, idx := range specialIndexes {
					if idx == uint64(i) {
						dataIndex = j
						break
					}
				}
				// check if the data is correct
				if ans0[i]^ans1[i] != data[dataIndex] {
					t.Fatalf("Expected: %v Got: %v", ans0[i], ans1[i])
				}
			} else {
				// check if the data is 0
				if ans0[i]^ans1[i] != 0 {
					fmt.Printf("indices[i] = %v\n", uint64(i))
					fmt.Printf("ans0 = %v\n", ans0)
					fmt.Printf("ans1 = %v\n", ans1)
					fmt.Printf("data = %v\n", data)
					t.Fatalf("Expected: %v Got: %v", 0, ans0[i]^ans1[i])
				}
			}
		}
	}
}

func BenchmarkDPFFullDomain(b *testing.B) {
	// different dataSize
	dataSizes := []int{10, 100, 1000, 10000, 100000}
	for _, dataSize := range dataSizes {
		prfKey := GeneratePRFKey()
		client := DPFInitialize(prfKey)
		server := DPFInitialize(prfKey)

		rangeSize := 6 // log2(64)
		specialIndex := uint64(rand.Intn(1 << rangeSize))
		data := make([]byte, dataSize)
		rand.Read(data)

		keyA, keyB := client.GenDPFKeys(specialIndex, uint(rangeSize), uint(dataSize), data)

		// time the full domain evaluation
		start := time.Now()
		ans0 := server.FullDomainEval(keyA)
		ans1 := server.FullDomainEval(keyB)
		elapsed := time.Since(start)

		// Verify that the results are consistent
		if len(ans0) != len(ans1) {
			b.Fatalf("DPF FullDomain failed for dataSize: %d", dataSize)
		}
		fmt.Printf("DPF FullDomain time: %s, dataSize: %d, resultSize: %d\n", elapsed, dataSize, len(ans0))
	}
}

func BenchmarkVDPFVerification(b *testing.B) {
	// different dataSize
	dataSizes := []int{10, 100, 1000, 10000, 100000}
	for _, dataSize := range dataSizes {
		prfKey := GeneratePRFKey()
		hashKeys := GenerateVDPFHashKeys()
		server := VDPFInitialize(prfKey, hashKeys)
		client := VDPFInitialize(prfKey, hashKeys)

		rangeSize := 7 // log2(128)
		specialIndex := uint64(rand.Intn(dataSize))
		data := make([]byte, dataSize)
		rand.Read(data)

		keyA, keyB := client.GenVDPFKeys(specialIndex, uint(rangeSize), uint(dataSize), data)

		//full domain eval
		// time the evaluation & verification
		start := time.Now()
		_, pi0 := server.FullDomainVerEval(keyA)
		_, pi1 := server.FullDomainVerEval(keyB)

		//verification
		if !bytes.Equal(pi0, pi1) {
			b.Fatalf("VDPF Verification failed for dataSize: %d", dataSize)
		}
		elapsed := time.Since(start)
		fmt.Printf("VDPF Verification time: %s\n, dataSize: %d\n", elapsed, dataSize)
	}
}

func BenchmarkDMPFGenEval(b *testing.B) {
	// different dataSize
	dataSizes := []int{10, 100, 1000, 10000, 100000}
	for _, dataSize := range dataSizes {
		prfKey := GeneratePRFKey()
		client := DMPFInitialize(prfKey)
		server := DMPFInitialize(prfKey)

		rangeSize := 6 // log2(64)
		rangePoint := 4
		specialIndexes := make([]uint64, rangePoint)
		used := make(map[uint64]bool)
		num := 1 << rangeSize
		for i := 0; i < rangePoint; {
			idx := uint64(rand.Intn(num))
			if !used[idx] {
				used[idx] = true
				specialIndexes[i] = idx
				i++
			}
		}
		slices.Sort(specialIndexes)
		data := make([]byte, rangePoint*dataSize)
		rand.Read(data)

		// time the key generation & evaluation
		start := time.Now()
		keyA, keyB := client.GenDMPFKeys(specialIndexes, uint(rangeSize), uint(rangePoint), uint(dataSize), data)

		// Evaluate for all special indices
		for j := 0; j < rangePoint; j++ {
			_ = server.EvalDMPF(keyA, specialIndexes[j])
			_ = server.EvalDMPF(keyB, specialIndexes[j])
		}
		elapsed := time.Since(start)
		fmt.Printf("DMPF GenEval time: %s, dataSize: %d\n", elapsed, dataSize)
	}
}

func BenchmarkDMPFFullDomain(b *testing.B) {
	// different dataSize
	dataSizes := []int{10, 100, 1000, 10000, 100000}
	for _, dataSize := range dataSizes {
		prfKey := GeneratePRFKey()
		client := DMPFInitialize(prfKey)
		server := DMPFInitialize(prfKey)

		rangeSize := 6 // log2(64)
		rangePoint := 10
		specialIndexes := make([]uint64, rangePoint)
		used := make(map[uint64]bool)
		num := 1 << rangeSize
		for i := 0; i < rangePoint; {
			idx := uint64(rand.Intn(num))
			if !used[idx] {
				used[idx] = true
				specialIndexes[i] = idx
				i++
			}
		}
		slices.Sort(specialIndexes)
		data := make([]byte, rangePoint*dataSize)
		rand.Read(data)

		keyA, keyB := client.GenDMPFKeys(specialIndexes, uint(rangeSize), uint(rangePoint), uint(dataSize), data)

		// time the full domain evaluation
		start := time.Now()
		ans0 := server.FullDomainEval(keyA)
		ans1 := server.FullDomainEval(keyB)
		elapsed := time.Since(start)

		// Verify that the results are consistent
		if len(ans0) != len(ans1) {
			b.Fatalf("DMPF FullDomain failed for dataSize: %d", dataSize)
		}
		fmt.Printf("DMPF FullDomain time: %s, dataSize: %d, resultSize: %d\n", elapsed, dataSize, len(ans0))
	}
}

// func Benchmark2PartyServerInit(b *testing.B) {

// 	prfKey := GeneratePRFKey()
// 	client := DPFInitialize(prfKey)

// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		DPFInitialize(prfKey)
// 	}
// }

// func Benchmark2Party64BitKeywordEval(b *testing.B) {

// 	prfKey := GeneratePRFKey()
// 	client := ClientDPFInitialize(prfKey)
// 	keyA, _ := client.GenDPFKeys(1, 64)
// 	server := ServerDPFInitialize(client.PrfKey)

// 	indices := make([]uint64, 100)
// 	for i := 0; i < len(indices); i++ {
// 		indices[i] = rand.Uint64()
// 	}
// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		server.BatchEval(keyA, indices)
// 	}
// }

// func Benchmark2PartyFullDomainEval(b *testing.B) {

// 	prfKey := GeneratePRFKey()
// 	client := ClientDPFInitialize(prfKey)
// 	keyA, _ := client.GenDPFKeys(1, 20)
// 	server := ServerDPFInitialize(client.PrfKey)

// 	indices := make([]uint64, 1)
// 	indices[0] = 1

// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		server.FullDomainEval(keyA)
// 	}
// }

// func Benchmark2Party64BitVerifiableKeywordEval(b *testing.B) {

// 	hashKeys := GenerateVDPFHashKeys()
// 	prfKey := GeneratePRFKey()

// 	client := ClientVDPFInitialize(prfKey, hashKeys)
// 	keyA, _ := client.GenDPFKeys(1, 64)
// 	server := ServerVDPFInitialize(prfKey, hashKeys)

// 	indices := make([]uint64, 10)
// 	for i := 0; i < len(indices); i++ {
// 		indices[i] = rand.Uint64()
// 	}

// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		server.BatchVerEval(keyA, indices)
// 	}
// }

// func BenchmarkDPFGen(b *testing.B) {

// 	b.ResetTimer()

// 	prfKey := GeneratePRFKey()

// 	for i := 0; i < b.N; i++ {

// 		client := ClientDPFInitialize(prfKey)
// 		client.GenDPFKeys(1, 64)
// 		DestroyDPFContext(client.ctx)
// 	}
// }
