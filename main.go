package main

import (
	"fmt"
	filesystem "github.com/harryfpayne/password-manager/cmd/file-system"
	"github.com/harryfpayne/password-manager/cmd/vault"
)

func main() {
	v := vault.NewVault()
	v.Profiles = append(v.Profiles, vault.Profile{
		Email:                   "a@b.c",
		EncryptedMasterPassword: "alskdjf",
	})

	cfg := filesystem.NewConfig()
	err := cfg.WriteVault(&v)
	if err != nil {
		panic(err)
	}

	v2, err := cfg.ReadVault()
	if err != nil {
		panic(err)
	}

	fmt.Println(v2)
}
