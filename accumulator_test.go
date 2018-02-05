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
		16, 147, 163, 19, 88, 88, 30, 123, 46, 66, 188, 141, 25, 216, 168, 22, 206, 48, 91, 170, 40, 84, 140, 119, 18, 167, 211, 154, 182, 64, 169, 138, 47, 170, 79, 60, 84, 83, 7, 229, 64, 141, 88, 252, 42, 250, 246, 186, 115, 87, 83, 254, 194, 124, 78, 146, 37, 17, 128, 137, 118, 241, 153, 25, 211, 239, 168, 27, 30, 41, 103, 57, 130, 125, 121, 187, 16, 174, 163, 153, 66, 68, 63, 187, 74, 81, 115, 12, 84, 28, 244, 225, 167, 199, 237, 125, 31, 32, 142, 108,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	acc.addRandomEvent(0, 0, make([]byte, 32))
	acc.addRandomEvent(0, 0, make([]byte, 32))
	out = acc.RandomData(100)
	correct = []byte{95, 253, 121, 144, 199, 185, 155, 208, 171, 168, 7, 114, 178, 28, 50, 224, 83, 38, 235, 55, 63, 59, 54, 36, 236, 217, 251, 238, 7, 87, 143, 255, 218, 48, 19, 34, 146, 89, 154, 8, 165, 127, 154, 116, 191, 125, 5, 137, 233, 40, 186, 16, 90, 148, 214, 8, 199, 174, 122, 57, 6, 240, 40, 45, 184, 181, 113, 38, 109, 5, 57, 191, 148, 111, 137, 3, 0, 138, 42, 97, 134, 65, 210, 146, 164, 12, 12, 175, 32, 50, 202, 41, 226, 216, 162, 2, 253, 231, 210, 146,}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	time.Sleep(200 * time.Millisecond)

	out = acc.RandomData(100)
	correct = []byte{182, 132, 196, 200, 145, 7, 95, 180, 79, 238, 116, 17, 156, 151, 71, 35, 119, 166, 4, 26, 223, 141, 242, 2, 5, 60, 232, 192, 245, 28, 42, 147, 179, 226, 213, 32, 56, 233, 83, 253, 69, 86, 68, 28, 29, 127, 249, 252, 128, 115, 88, 39, 186, 146, 30, 255, 132, 211, 94, 73, 201, 151, 97, 161, 214, 227, 176, 42, 151, 152, 83, 53, 173, 197, 130, 227, 58, 141, 130, 89, 66, 114, 82, 156, 214, 25, 60, 154, 25, 194, 226, 120, 216, 211, 249, 115, 172, 42, 226, 70,}
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
