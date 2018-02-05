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

func TestOutput(t *testing.T) {
	// The reference values in this function are generated using the
	// "Python Cryptography Toolkit",
	// https://www.dlitz.net/software/pycrypto/ .

	rng := NewGenerator()
	rng.reset()

	rng.Reseed([]byte{1, 2, 3, 4})
	out := rng.PseudoRandomData(100)
	correct := []byte{
		46, 144, 196, 54, 218, 98, 33, 223, 85, 107, 31, 195, 208, 196, 44, 236, 200, 13, 161, 36, 66, 27, 116, 152, 116, 124, 190, 193, 121, 57, 9, 223, 236, 171, 174, 250, 217, 84, 5, 176, 47, 183, 112, 200, 41, 187, 138, 244, 165, 202, 240, 95, 75, 116, 232, 233, 115, 28, 29, 212, 3, 156, 128, 86, 49, 231, 167, 210, 156, 52, 76, 91, 236, 229, 253, 143, 141, 175, 217, 167, 247, 53, 81, 127, 192, 246, 242, 35, 75, 149, 42, 145, 208, 111, 169, 175, 188, 19, 18, 20,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	out = rng.PseudoRandomData(1<<20 + 100)[1<<20:]
	correct = []byte{
		215, 192, 214, 200, 94, 19, 31, 195, 34, 172, 112, 8, 137, 103, 83, 219, 242, 202, 22, 235, 178, 71, 96, 53, 140, 184, 238, 19, 230, 102, 38, 192, 235, 111, 125, 217, 83, 214, 153, 19, 171, 28, 123, 33, 229, 129, 39, 140, 254, 201, 184, 81, 1, 157, 92, 100, 62, 194, 101, 201, 158, 146, 249, 131, 66, 105, 9, 60, 24, 155, 0, 154, 157, 37, 93, 123, 103, 23, 119, 115, 25, 225, 28, 33, 198, 43, 22, 85, 22, 224, 239, 247, 12, 157, 224, 78, 92, 110, 207, 52,
	}
	if bytes.Compare(out, correct) != 0 {
		t.Error("wrong RNG output", out)
	}

	rng.Reseed([]byte{5})
	out = rng.PseudoRandomData(100)
	correct = []byte{
		192, 254, 179, 2, 112, 177, 104, 141, 191, 224, 158, 71, 244, 238, 200, 171, 197, 233, 76, 0, 54, 28, 180, 85, 177, 159, 251, 9, 65, 253, 24, 182, 50, 179, 94, 164, 210, 249, 193, 41, 72, 221, 39, 251, 129, 167, 213, 238, 245, 142, 231, 60, 26, 148, 151, 14, 62, 184, 167, 144, 217, 231, 122, 71, 103, 174, 211, 196, 174, 253, 12, 6, 200, 5, 62, 167, 61, 179, 97, 32, 17, 82, 12, 146, 229, 109, 225, 43, 91, 155, 142, 240, 28, 88, 249, 178, 126, 79, 86, 49,
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
