package timecrypt

import "math"

// Fixed-point encoding of float64 sample values, so floats (e.g. Prometheus
// samples) can ride the additively-homomorphic int64 HEAC scheme: sums of
// fixed-point encodings are the fixed-point encoding of the sum.
//
// This is not part of the Java crypto module (the Java client only encrypts
// integer metadata); it is the glue Prometheus needs for float values.

// DefaultFixedPointScale keeps 6 decimal digits, leaving ~2^43 of integer
// headroom for range sums.
const DefaultFixedPointScale = 1e6

// FloatToFixed encodes v as a fixed-point int64 with the given scale.
func FloatToFixed(v, scale float64) int64 {
	return int64(math.Round(v * scale))
}

// FixedToFloat decodes a fixed-point int64 (or a sum of them) back to float64.
func FixedToFloat(v int64, scale float64) float64 {
	return float64(v) / scale
}
