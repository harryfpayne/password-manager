package file_system

import (
	"encoding/json"
	"fmt"
	"github.com/harryfpayne/password-manager/cmd/vault"
	"os"
)

func (cfg Config) ReadVault() (*vault.Vault, error) {
	file, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		return nil, err
	}

	var v vault.Vault
	err = json.Unmarshal(file, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

func (cfg Config) WriteVault(v *vault.Vault) error {
	if v == nil {
		return fmt.Errorf("invalid vault")
	}
	file, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return os.WriteFile(cfg.FilePath, file, os.ModePerm)
}
