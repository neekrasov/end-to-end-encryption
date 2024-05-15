package aes

import (
	"math/big"
	"os"
	"os/exec"

	"github.com/pkg/errors"
)

func Encrypt(plainText string, key *big.Int) ([]byte, error) {
	plainTextFile, err := os.CreateTemp("", "plainText")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create plain text temp file")
	}
	defer plainTextFile.Close()
	defer os.Remove(plainTextFile.Name())

	if _, err := plainTextFile.Write([]byte(plainText)); err != nil {
		return nil, errors.Wrap(err, "failed write to plain text temp file")
	}

	keyFile, err := os.CreateTemp("", "key")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create key temp file")
	}
	defer keyFile.Close()
	defer os.Remove(keyFile.Name())

	if _, err := keyFile.Write(key.Bytes()); err != nil {
		return nil, errors.Wrap(err, "failed write to key temp file")
	}

	encFile, err := os.CreateTemp("", "enc")
	if err != nil {
		return nil, errors.Wrap(err, "failed write file for encryption")
	}
	defer encFile.Close()
	defer os.Remove(encFile.Name())

	cmd := exec.Command(
		"openssl", "enc", "-aes-256-ofb",
		"-in", plainTextFile.Name(),
		"-out", encFile.Name(),
		"-pass", "file:"+keyFile.Name(),
		"-pbkdf2", "-iter", "10000",
	)
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrap(err, "failed encrypt plain text")
	}

	return os.ReadFile(encFile.Name())
}

func Decrypt(cipherText []byte, key *big.Int) (string, error) {
	encFile, err := os.CreateTemp("", "enc")
	if err != nil {
		return "", errors.Wrap(err, "failed to create encrypted temp file")
	}
	defer encFile.Close()
	defer os.Remove(encFile.Name())

	if _, err := encFile.Write(cipherText); err != nil {
		return "", errors.Wrap(err, "failed to write cypher text to temp file")
	}

	keyFile, err := os.CreateTemp("", "key")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp key file")
	}
	defer keyFile.Close()
	defer os.Remove(keyFile.Name())

	if _, err := keyFile.Write(key.Bytes()); err != nil {
		return "", errors.Wrap(err, "failed write to temp key file")
	}

	decFile, err := os.CreateTemp("", "dec")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file for decryption")
	}
	defer decFile.Close()
	defer os.Remove(encFile.Name())

	cmd := exec.Command(
		"openssl", "enc", "-d", "-aes-256-ofb",
		"-in", encFile.Name(),
		"-out", decFile.Name(),
		"-pass", "file:"+keyFile.Name(),
		"-pbkdf2", "-iter", "10000",
	)
	if err := cmd.Run(); err != nil {
		return "", errors.Wrap(err, "failed to decrypt cypher text")
	}

	plainText, err := os.ReadFile(decFile.Name())
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
