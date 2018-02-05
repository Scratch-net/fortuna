// accumulator_test.go - unit tests for accumulator.go
// Copyright (C) 2013  Jochen Voss <voss@seehuhn.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package fortuna

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccumulator(t *testing.T) {
	// The reference values in this function are generated using the
	// "Python Cryptography Toolkit",
	// https://www.dlitz.net/software/pycrypto/ .

	acc, _ := NewRNG("")
	acc.gen.reset()

	acc.addRandomEvent(0, 0, make([]byte, 32))
	acc.addRandomEvent(0, 0, make([]byte, 32))
	for i := uint(0); i < 1000; i++ {
		acc.addRandomEvent(1, i, []byte{1, 2})
	}
	out := acc.RandomData(100)
	correct := []byte{
		143, 243, 164, 14, 173, 156, 140, 179, 154, 120, 131, 113, 3, 149, 105, 146, 111, 247, 210, 67, 195, 2, 35, 139, 59, 25, 212, 165, 252, 114, 18, 156, 17, 137, 169, 51, 250, 99, 110, 202, 128, 215, 127, 245, 87, 125, 84, 145, 46, 169, 127, 200, 116, 13, 137, 58, 163, 96, 184, 103, 141, 95, 211, 151, 101, 181, 23, 22, 126, 1, 184, 245, 164, 35, 13, 252, 0, 59, 101, 188, 33, 73, 70, 85, 79, 69, 199, 145, 79, 144, 65, 145, 205, 41, 207, 251, 184, 168, 24, 140,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	acc.addRandomEvent(0, 0, make([]byte, 32))
	acc.addRandomEvent(0, 0, make([]byte, 32))
	out = acc.RandomData(100)
	correct = []byte{224, 51, 198, 91, 56, 39, 29, 220, 241, 242, 240, 102, 218, 39, 3, 17, 49, 94, 142, 216, 24, 84, 104, 225, 41, 170, 116, 192, 36, 157, 21, 67, 190, 88, 77, 226, 227, 234, 179, 167, 46, 12, 177, 12, 169, 137, 206, 104, 46, 247, 28, 68, 75, 88, 21, 32, 55, 61, 236, 86, 81, 106, 156, 113, 90, 44, 29, 203, 235, 165, 31, 149, 7, 219, 121, 12, 104, 115, 43, 53, 122, 59, 115, 157, 252, 4, 188, 187, 119, 196, 118, 49, 50, 233, 17, 17, 10, 48, 148, 117}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	time.Sleep(200 * time.Millisecond)

	out = acc.RandomData(100)
	correct = []byte{186, 233, 87, 143, 61, 201, 124, 48, 212, 65, 191, 62, 250, 35, 128, 36, 184, 161, 34, 94, 202, 181, 83, 79, 161, 70, 223, 190, 160, 179, 49, 163, 36, 99, 173, 182, 92, 90, 10, 157, 121, 17, 88, 187, 171, 161, 83, 123, 111, 167, 173, 98, 249, 144, 121, 144, 61, 52, 211, 109, 46, 83, 135, 141, 115, 231, 179, 25, 69, 25, 59, 183, 137, 47, 31, 115, 97, 29, 172, 79, 24, 49, 91, 164, 54, 92, 52, 231, 184, 32, 137, 132, 77, 162, 155, 239, 55, 207, 18, 60}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}
}

func TestClose(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	seedFileName := filepath.Join(tempDir, "seed")

	for _, name := range []string{"", seedFileName} {
		acc, err := NewRNG(name)
		if err != nil {
			t.Error(err)
		}
		acc.RandomData(1)
		acc.Close()
		caughtAccessAfterClose := func() (hasPaniced bool) {
			defer func() {
				if r := recover(); r != nil {
					hasPaniced = true
				}
			}()
			acc.RandomData(1)
			return false
		}()
		if !caughtAccessAfterClose {
			t.Error("failed to detect RNG access after close")
		}
	}
}

func TestReseedingDuringClose(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	seedFileName := filepath.Join(tempDir, "seed")

	acc, err := NewRNG(seedFileName)
	if err != nil {
		t.Error(err)
	}

	buf := make([]byte, 32)
	sink := acc.NewEntropyDataSink()
	for i := 0; i < numPools*32/minPoolSize; i++ {
		sink <- buf
	}
	close(sink)

	acc.Close()
}

func accumulatorRead(b *testing.B, n int) {
	acc, _ := NewRNG("")
	buffer := make([]byte, n)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// acc.Read is guaranteed to return the full data in one go
		// and not to return an error.
		acc.Read(buffer)
	}
}

func BenchmarkAccumulatorRead16(b *testing.B) { accumulatorRead(b, 16) }
func BenchmarkAccumulatorRead32(b *testing.B) { accumulatorRead(b, 32) }
func BenchmarkAccumulatorRead1k(b *testing.B) { accumulatorRead(b, 1024) }

func cryptoRandRead(b *testing.B, n int) {
	buffer := make([]byte, n)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
			b.Fatalf(err.Error())
		}
	}
}

func BenchmarkCryptoRandRead16(b *testing.B) { cryptoRandRead(b, 16) }
func BenchmarkCryptoRandRead32(b *testing.B) { cryptoRandRead(b, 32) }
func BenchmarkCryptoRandRead1k(b *testing.B) { cryptoRandRead(b, 1024) }

func TestRandInt63(t *testing.T) {
	acc, _ := NewRNG("")
	r := acc.Int63()
	if r < 0 {
		t.Error("Invalid random output")
	}
}

func TestRandSeed(t *testing.T) {
	acc, _ := NewRNG("")
	defer func() {
		if r := recover(); r == nil {
			t.Error("Failed to panic")
		}
	}()
	acc.Seed(0)
}

// compile-time test: Accumulator implements the rand.Source interface
var _ mrand.Source = &Accumulator{}
