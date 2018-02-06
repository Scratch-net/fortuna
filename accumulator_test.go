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
		13, 69, 56, 109, 141, 138, 113, 95, 127, 245, 182, 69, 100, 65, 226, 216, 132, 119, 167, 148, 215, 253, 198, 128, 87, 10, 241, 136, 112, 178, 113, 155, 222, 181, 175, 184, 194, 133, 132, 199, 1, 107, 133, 183, 230, 224, 66, 244, 236, 32, 54, 109, 203, 192, 158, 91, 224, 118, 211, 218, 78, 83, 143, 80, 51, 201, 168, 236, 27, 3, 164, 246, 108, 194, 236, 53, 246, 13, 149, 34, 139, 142, 141, 83, 164, 166, 70, 253, 209, 188, 222, 20, 150, 131, 128, 76, 191, 239, 140, 219,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	acc.addRandomEvent(0, 0, make([]byte, 32))
	acc.addRandomEvent(0, 0, make([]byte, 32))
	out = acc.RandomData(100)
	correct = []byte{
		128, 162, 173, 80, 167, 236, 238, 209, 71, 236, 33, 191, 219, 242, 120, 92, 208, 184, 72, 88, 46, 135, 206, 130, 188, 131, 124, 210, 219, 53, 206, 134, 132, 142, 45, 140, 168, 163, 97, 170, 59, 129, 59, 49, 179, 210, 18, 240, 22, 66, 151, 200, 62, 48, 127, 167, 99, 4, 137, 110, 58, 255, 195, 55, 129, 74, 53, 217, 179, 219, 72, 41, 208, 148, 210, 159, 108, 140, 216, 32, 36, 213, 29, 183, 151, 216, 143, 134, 193, 227, 31, 125, 71, 196, 232, 2, 27, 90, 99, 36,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	time.Sleep(200 * time.Millisecond)

	out = acc.RandomData(100)
	correct = []byte{
		251, 221, 252, 169, 162, 63, 79, 229, 91, 28, 159, 133, 19, 50, 239, 37, 141, 37, 178, 235, 86, 72, 60, 252, 125, 234, 248, 204, 81, 173, 118, 128, 246, 227, 174, 226, 86, 20, 227, 188, 185, 108, 57, 95, 162, 84, 250, 190, 56, 202, 122, 171, 237, 173, 61, 116, 252, 3, 128, 208, 56, 39, 73, 60, 18, 47, 37, 96, 107, 108, 67, 176, 254, 191, 235, 78, 170, 185, 202, 184, 26, 182, 9, 140, 0, 31, 34, 49, 195, 139, 20, 142, 178, 240, 187, 97, 184, 182, 170, 121,
	}
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
