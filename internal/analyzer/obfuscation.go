package analyzer

import (
	"encoding/base64"
	"math"
)

const (
	minEncodedLiteral = 64
	maxDecodedLiteral = 64 << 10
	maxDecodeLayers   = 2
)

func obfuscationOccurrences(raw []byte) int {
	occurrences := 0
	for _, literal := range quotedLiterals(raw) {
		if denseEscapes(literal) || encodedLiteral(literal) {
			occurrences++
		}
	}
	return occurrences
}

func quotedLiterals(raw []byte) [][]byte {
	var result [][]byte
	for index := 0; index < len(raw); index++ {
		quote := raw[index]
		if quote != '\'' && quote != '"' && quote != '`' {
			continue
		}
		start := index + 1
		for index++; index < len(raw); index++ {
			if raw[index] == '\\' {
				index++
				continue
			}
			if raw[index] == quote {
				if index-start <= maxDecodedLiteral {
					result = append(result, raw[start:index])
				}
				break
			}
		}
	}
	return result
}

func denseEscapes(value []byte) bool {
	if len(value) < minEncodedLiteral {
		return false
	}
	escapes := 0
	for index := 0; index+1 < len(value); index++ {
		if value[index] == '\\' && (value[index+1] == 'x' || value[index+1] == 'u') {
			escapes++
			index++
		}
	}
	return escapes >= 8 && escapes*8 >= len(value)
}

func encodedLiteral(value []byte) bool {
	current := append([]byte(nil), value...)
	defer clear(current)
	for layer := 0; layer < maxDecodeLayers; layer++ {
		if len(current) < minEncodedLiteral || len(current) > maxDecodedLiteral || len(current)%4 != 0 {
			return false
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(current)))
		count, err := base64.StdEncoding.Decode(decoded, current)
		clear(current)
		if err != nil || count == 0 || count > maxDecodedLiteral {
			clear(decoded)
			return false
		}
		decoded = decoded[:count]
		if shannonEntropy(decoded) >= 4.5 {
			clear(decoded)
			return true
		}
		current = decoded
	}
	return false
}

func shannonEntropy(value []byte) float64 {
	if len(value) == 0 {
		return 0
	}
	var counts [256]int
	for _, item := range value {
		counts[item]++
	}
	result := 0.0
	for _, count := range counts {
		if count > 0 {
			probability := float64(count) / float64(len(value))
			result -= probability * math.Log2(probability)
		}
	}
	return result
}
