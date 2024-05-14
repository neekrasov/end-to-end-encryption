package rsa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"strconv"
	"strings"
)

type (
	PublicKey struct {
		N *big.Int
		E *big.Int
	}

	PrivateKey struct {
		N *big.Int
		D *big.Int
	}
)

func GenerateKeys(bits int) (*PublicKey, *PrivateKey, error) {
	p, err := generatePrime(bits)
	if err != nil {
		return nil, nil, err
	}
	q, err := generatePrime(bits)
	if err != nil {
		return nil, nil, err
	}

	// Calc n = p * q
	n := new(big.Int).Mul(p, q)

	// Calc phi(n) = (p-1) * (q-1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	// 1 < e < phi(n) и gcd(e, phi(n)) = 1
	e := new(big.Int).Sub(phi, new(big.Int).SetInt64(1))
	for {
		for {
			e = new(big.Int).Sub(e, new(big.Int).SetInt64(1))
			if e.ProbablyPrime(0) {
				g, _, _ := ExtendedGCD(e, phi)
				if g.Cmp(big.NewInt(1)) == 0 {
					break
				}
			}
		}

		d, err := ModInverse(e, phi)
		if err != nil || d.Cmp(e) == 0 {
			continue
		}

		return &PublicKey{N: n, E: e}, &PrivateKey{N: n, D: d}, nil
	}
}

func Encrypt(message *big.Int, publicKey *PublicKey) *big.Int {
	return new(big.Int).Exp(message, publicKey.E, publicKey.N)
}

func Decrypt(ciphertext *big.Int, privateKey *PrivateKey) *big.Int {
	return new(big.Int).Exp(ciphertext, privateKey.D, privateKey.N)
}

func Sign(message *big.Int, privateKey *PrivateKey) *big.Int {
	return new(big.Int).Exp(message, privateKey.D, privateKey.N)
}

func Verify(signature, message *big.Int, publicKey *PublicKey) bool {
	decryptedSignature := new(big.Int).Exp(signature, publicKey.E, publicKey.N)

	return decryptedSignature.Cmp(message) == 0
}

func ModInverse(a, n *big.Int) (*big.Int, error) {
	g, x, _ := ExtendedGCD(a, n)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("modular inverse does not exist")
	}

	return x.Mod(x, n), nil
}

func ExtendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	zero := big.NewInt(0)

	if a.Cmp(zero) == 0 {
		return b, zero, big.NewInt(1)
	}

	gcd, x1, y1 := ExtendedGCD(new(big.Int).Mod(b, a), a)

	return gcd, new(big.Int).Sub(y1, new(big.Int).Mul(new(big.Int).Div(b, a), x1)), x1
}

func cmdRun(args ...string) (string, error) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to run cmd: %s; stderr %s; stdout %s;", err.Error(), stderr.String(), stdout.String())
	}

	return stdout.String(), nil
}

func generatePrime(bits int) (*big.Int, error) {
	output, err := cmdRun("openssl", "prime", "-generate", "-bits", strconv.Itoa(bits), "-hex")
	if err != nil {
		return nil, errors.New("error generating: %s")
	}

	prime, ok := new(big.Int).SetString(strings.TrimSpace(string(output)), 16)
	if !ok {
		return nil, fmt.Errorf("failed to generate prime %d bits", bits)
	}

	return prime, nil
}

func HashSHA256(val string) (*big.Int, error) {
	var out bytes.Buffer

	cmd := exec.Command("openssl", "dgst", "-sha256", "-hex")
	cmd.Stdin = strings.NewReader(val)
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	parts := strings.Split(strings.TrimSpace(out.String()), " ")
	if len(parts) != 2 {
		return nil, errors.New("unexpected output format")
	}

	m, _ := new(big.Int).SetString(parts[1], 16)

	return m, nil
}
