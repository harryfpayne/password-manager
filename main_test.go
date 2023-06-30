package main

import (
	filesystem "github.com/harryfpayne/password-manager/cmd/file-system"
	"github.com/harryfpayne/password-manager/cmd/vault"
	"testing"
)

func Test_AbleToRetreivePassword(t *testing.T) {
	email := "a@b.c"
	password := "password"
	v, err := vault.NewVault(email, password)
	if err != nil {
		panic(err)
	}

	err = v.CreateEntry(email, password, "https://www.google.com", "google-password")
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

	_password, err := v2.GetPassword("https://www.google.com")
	if err != nil {
		panic(err)
	}

	if _password != "google-password" {
		t.Errorf("Expected password to be %s, got %s", "google-password", _password)
	}
}

func Test_ProfilePasswordWorks(t *testing.T) {
	email := "a@b.c"
	password := "password"
	v, err := vault.NewVault(email, password)
	if err != nil {
		panic(err)
	}

	err = v.CreateEntry(email, password, "https://www.google.com", "google-password")
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

	err = v2.Login(email, "bad-password")
	if err != nil {
		panic(err)
	}

	_password, err := v2.GetPassword("https://www.google.com")
	if err != nil {
		panic(err)
	}

	if _password == "google-password" {
		t.Errorf("Expected password to be invalid, got equal password")
	}
}
