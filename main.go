package main

import (
	"fmt"
	filesystem "github.com/harryfpayne/password-manager/cmd/file-system"
	"github.com/harryfpayne/password-manager/cmd/vault"
)

const email = "a@b.c"
const password = "real-password"

func main() {
	v, err := vault.NewVault(email, password)
	if err != nil {
		panic(err)
	}

	googlePassword := "google-password"
	err = v.CreateEntry(email, password, "www.google.com", googlePassword)
	if err != nil {
		panic(err)
	}

	cfg := filesystem.NewConfig()
	err = cfg.WriteVault(&v)
	if err != nil {
		panic(err)
	}

	v2, err := cfg.ReadVault()
	if err != nil {
		panic(err)
	}

	err = v2.Login(email, password)
	if err != nil {
		panic(err)
	}

	_password, err := v2.GetPassword("www.google.com")
	if err != nil {
		panic(err)
	}

	fmt.Println("Got password: ", _password, _password == googlePassword)
}
