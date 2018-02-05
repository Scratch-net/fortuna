// generator_test.go - unit tests for generator.go
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
	"math"
	"math/rand"
	"testing"
)

func TestConstants(t *testing.T) {

}

func TestOutput(t *testing.T) {
	// The reference values in this function are generated using the
	// "Python Cryptography Toolkit",
	// https://www.dlitz.net/software/pycrypto/ .

	rng := NewGenerator()
	rng.reset()

	rng.Reseed([]byte{1, 2, 3, 4})
	out := rng.PseudoRandomData(100)
	correct := []byte{
		223, 9, 57, 106, 18, 36, 220, 141, 234, 145, 212, 63, 159, 251, 236, 127, 161, 154, 116, 173, 105, 81, 18, 251, 16, 3, 162, 193, 224, 222, 228, 228, 180, 207, 168, 228, 75, 13, 21, 97, 109, 48, 22, 90, 155, 201, 22, 85, 75, 129, 222, 54, 240, 254, 169, 217, 119, 239, 57, 222, 237, 55, 40, 217, 176, 87, 43, 203, 251, 231, 82, 160, 254, 58, 175, 26, 44, 138, 204, 27, 30, 54, 103, 168, 147, 32, 2, 75, 29, 0, 74, 131, 93, 132, 97, 179, 89, 140, 218, 86,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	out = rng.PseudoRandomData(1<<20 + 100)[1<<20:]
	correct = []byte{
		191, 165, 64, 21, 6, 66, 189, 246, 228, 195, 203, 197, 68, 48, 183, 176, 64, 69, 218, 77, 66, 194, 185, 167, 234, 237, 84, 42, 231, 206, 37, 253, 205, 16, 136, 181, 117, 144, 16, 222, 249, 130, 10, 59, 124, 219, 30, 190, 113, 239, 90, 89, 146, 154, 243, 141, 44, 111, 51, 246, 81, 84, 95, 77, 198, 177, 160, 224, 244, 141, 177, 122, 58, 191, 221, 126, 36, 100, 209, 190, 120, 97, 68, 252, 110, 161, 80, 252, 3, 204, 95, 227, 214, 42, 107, 255, 53, 207, 48, 191,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	rng.Reseed([]byte{5})
	out = rng.PseudoRandomData(100)
	correct = []byte{
		169, 57, 172, 193, 115, 140, 160, 191, 167, 244, 234, 141, 55, 153, 89, 142, 215, 36, 90, 188, 82, 220, 139, 106, 197, 141, 91, 246, 209, 177, 9, 251, 134, 40, 195, 144, 238, 85, 15, 253, 49, 228, 111, 198, 230, 162, 117, 73, 237, 21, 35, 104, 193, 251, 237, 99, 231, 149, 9, 169, 93, 20, 87, 103, 117, 206, 36, 183, 76, 252, 222, 76, 226, 81, 140, 216, 19, 38, 5, 157, 99, 43, 140, 26, 66, 188, 206, 131, 12, 25, 103, 126, 8, 30, 238, 149, 123, 143, 152, 71,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}
}

func TestReseed(t *testing.T) {
	rng := NewGenerator()
	if len(rng.key) != 32 {
		t.Error("wrong key size")
	}

	rng.Reseed(nil)
	if len(rng.key) != 32 {
		t.Error("wrong key size after reseeding")
	}
}

func TestSeed(t *testing.T) {
	rng := NewGenerator()

	for _, seed := range []int64{0, 1, 1 << 62} {
		rng.Seed(seed)
		x := rng.PseudoRandomData(1000)
		rng.Seed(seed)
		y := rng.PseudoRandomData(1000)
		if bytes.Compare(x, y) != 0 {
			t.Error(".Seed() doesn't determine generator state")
		}
	}
}

func TestPrng(t *testing.T) {
	rng := NewGenerator()
	rng.Seed(123)

	prng := rand.New(rng)
	n := 1000000
	pos := 0
	for i := 0; i < n; i++ {
		x := prng.NormFloat64()
		if x > 0 {
			pos++
		}
	}

	d := (float64(pos) - 0.5*float64(n)) / math.Sqrt(0.25*float64(n))
	if math.Abs(d) >= 4 {
		t.Error("wrong distribution")
	}
}

func BenchmarkReseed(b *testing.B) {
	rng := NewGenerator()
	seed := []byte{1, 2, 3, 4}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rng.Reseed(seed)
	}
}

func generator(b *testing.B, n uint) {
	rng := NewGenerator()
	rng.Seed(0)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rng.PseudoRandomData(n)
	}
}

func BenchmarkGenerator16(b *testing.B) { generator(b, 16) }
func BenchmarkGenerator32(b *testing.B) { generator(b, 32) }
func BenchmarkGenerator1k(b *testing.B) { generator(b, 1024) }

// compile-time test: Generator implements the rand.Source interface
var _ rand.Source = &Generator{}
