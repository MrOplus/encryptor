package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/alexflint/go-arg"
	"golang.org/x/term"
	"io"
	"os"
	"syscall"
)

func padKey(key []byte) []byte {
	paddedKey := make([]byte, 32)
	copy(paddedKey, key)
	return paddedKey
}
func encrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(padKey(key))
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(padKey(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func main() {
	var args struct {
		Mode   string `arg:"-m,--mode,required" help:"Mode to run in (e|d)"`
		Input  string `arg:"positional,required" help:"Input file to read"`
		Output string `arg:"positional,required" help:"Output file to write"`
	}
	arg.MustParse(&args)
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %s\n", err)
		os.Exit(1)
	}
	if len(password) < 8 {
		fmt.Fprintf(os.Stderr, "password must be at least 8 characters\n")
		os.Exit(1)
	}
	if len(password) > 32 {
		fmt.Fprintf(os.Stderr, "password must be at most 32 characters\n")
		os.Exit(1)
	}
	if len(password) < 32 {
		for i := len(password); i < 32; i++ {
			password = append(password, 0)
		}
	}
	if args.Mode == "e" {
		fmt.Println("Encrypting")
		content, err := os.ReadFile(args.Input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading file: %s\n", err)
			os.Exit(1)
		}
		encrypted, err := encrypt(password, string(content))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encrypting: %s\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(args.Output, []byte(encrypted), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing file: %s\n", err)
			os.Exit(1)

		}
	} else if args.Mode == "d" {
		fmt.Println("Decrypting")
		content, err := os.ReadFile(args.Input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading file: %s\n", err)
			os.Exit(1)
		}
		decrypted, err := decrypt(password, string(content))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decrypting: %s\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(args.Output, []byte(decrypted), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error writing file: %s\n", err)
			os.Exit(1)
		}
	}
}
