package main

import (
	"fmt"
	"log"
	"testing"
)

func TestJson(t *testing.T) {
	data, err := LoadBenchmarks("data/test.json")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed data: %+v\n", data)
}

func TestRegex(t *testing.T) {
	testStrings := []string{
		"BP/Paillier/Gen",
		"Core/BN/GCD-Batch(16)RSA-Modulus/1024",
		"Core/EC/Add/Ed25519",
		"Core/Hash/AES-GCM-128/1",
		"ZK/NI/Batch_16-DL-Ed25519/Prover",
	}

	for _, testString := range testStrings {
		fmt.Println(ParseBenchmarkName(testString))
	}

}
