package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMax 测试 Max 函数
func TestMax(t *testing.T) {
	tests := []struct {
		name     string
		weights  []int
		expected int
	}{
		{
			name:     "Normal case with positive numbers",
			weights:  []int{1, 5, 3, 9, 2},
			expected: 9,
		},
		{
			name:     "Single element",
			weights:  []int{42},
			expected: 42,
		},
		{
			name:     "Empty slice",
			weights:  []int{},
			expected: 0,
		},
		{
			name:     "All negative numbers",
			weights:  []int{-10, -5, -8, -2},
			expected: -2,
		},
		{
			name:     "Mixed positive and negative",
			weights:  []int{-5, 10, -3, 8},
			expected: 10,
		},
		{
			name:     "All equal numbers",
			weights:  []int{7, 7, 7, 7},
			expected: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Max(tt.weights)
			assert.Equal(t, tt.expected, result, "Max(%v) should return %d", tt.weights, tt.expected)
		})
	}
}

// TestGCD 测试 GCD 函数
func TestGCD(t *testing.T) {
	tests := []struct {
		name     string
		weights  []int
		expected int
	}{
		{
			name:     "Normal case with multiple numbers",
			weights:  []int{12, 18, 24},
			expected: 6,
		},
		{
			name:     "Single element",
			weights:  []int{15},
			expected: 15,
		},
		{
			name:     "Empty slice",
			weights:  []int{},
			expected: 0,
		},
		{
			name:     "All numbers are coprime",
			weights:  []int{7, 11, 13},
			expected: 1,
		},
		{
			name:     "All zeros",
			weights:  []int{0, 0, 0},
			expected: 0,
		},
		{
			name:     "Two numbers",
			weights:  []int{48, 18},
			expected: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GCD(tt.weights)
			assert.Equal(t, tt.expected, result, "GCD(%v) should return %d", tt.weights, tt.expected)
		})
	}
}

// TestGCDTwo 测试 GCDTwo 函数
func TestGCDTwo(t *testing.T) {
	tests := []struct {
		name     string
		a        int
		b        int
		expected int
	}{
		{
			name:     "Normal positive numbers",
			a:        48,
			b:        18,
			expected: 6,
		},
		{
			name:     "One zero",
			a:        15,
			b:        0,
			expected: 15,
		},
		{
			name:     "Both zeros",
			a:        0,
			b:        0,
			expected: 0,
		},
		{
			name:     "Equal numbers",
			a:        7,
			b:        7,
			expected: 7,
		},
		{
			name:     "Coprime numbers",
			a:        13,
			b:        17,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GCDTwo(tt.a, tt.b)
			assert.Equal(t, tt.expected, result, "GCDTwo(%d, %d) should return %d", tt.a, tt.b, tt.expected)
		})
	}
}
