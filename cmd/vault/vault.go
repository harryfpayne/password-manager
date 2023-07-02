package vault

import (
	"fmt"
	"github.com/harryfpayne/password-manager/cmd/crypto"
)

type Vault struct {
	Entries  []Entry   `json:"entries"`
	Profiles []Profile `json:"profiles"`
	Salt     string
}

type Profile struct {
	Email          string          `json:"email"`
	MasterPassword EncryptedString `json:"masterPassword"`
}

type Entry struct {
	Url          EncryptedString `json:"url"`
	ItemKey      EncryptedString `json:"itemKey"`
	ItemPassword EncryptedString `json:"itemPassword"`
}

const SALT_LENGTH = 16
const MASTER_PASSWORD_LENGTH = 32
const ITEM_KEY_LENGTH = 32

func NewVault(rootEmail, rootPassword string) (Vault, error) {
	v := Vault{
		Entries:  []Entry{},
		Profiles: []Profile{},
		Salt:     crypto.RandomString(SALT_LENGTH),
	}

	err := v.CreateProfile(crypto.RandomString(MASTER_PASSWORD_LENGTH), rootEmail, rootPassword)
	if err != nil {
		return Vault{}, err
	}
	return v, nil
}

func (v *Vault) CreateProfile(masterPassword string, email string, password string) error {
	profileMasterPassword := NewEncryptedString(masterPassword)

	derivedKey := crypto.GetDerivedKey(password, v.Salt)
	profileMasterPassword = profileMasterPassword.Encrypt(derivedKey)

	v.Profiles = append(v.Profiles, Profile{
		Email:          email,
		MasterPassword: profileMasterPassword,
	})
	return nil
}

func (v *Vault) CreateEntry(email, password, _url, _password string) error {
	masterPassword, err := v.getMasterPassword(email, password)
	if err != nil {
		return err
	}

	url := NewEncryptedString(_url).Encrypt(masterPassword.S())

	itemKey := NewEncryptedString(crypto.RandomString(ITEM_KEY_LENGTH))

	itemPassword := NewEncryptedString(_password).Encrypt(itemKey.S())

	itemKey = itemKey.Encrypt(masterPassword.S())

	v.Entries = append(v.Entries, Entry{
		Url:          url,
		ItemKey:      itemKey,
		ItemPassword: itemPassword,
	})
	return nil
}

func (v *Vault) GetPassword(_url string) (string, error) {
	var e Entry
	for _, e = range v.Entries {
		if e.Url.Encrypted {
			panic("tried reading password on locked vault")
		}

		if e.Url.S() == _url {
			break
		}
	}

	if e.Url.S() == "" {
		return "", fmt.Errorf("no entry found for url %s", _url)
	}

	if e.ItemKey.Encrypted {
		return "", fmt.Errorf("tried reading password on locked vault")
	}

	itemPassword := e.ItemPassword.Decrypt(e.ItemKey.S())
	return itemPassword.S(), nil
}

func (v *Vault) Login(email string, password string) error {
	masterPassword, err := v.getMasterPassword(email, password)
	if err != nil {
		return err
	}

	// Decrypt url and item key for each entry
	// Don't decrypt the passwords yet
	for i, entry := range v.Entries {
		if !entry.Url.Encrypted {
			continue
		}
		url := entry.Url.Decrypt(masterPassword.S())
		v.Entries[i].Url = url

		itemKey := entry.ItemKey.Decrypt(masterPassword.S())
		v.Entries[i].ItemKey = itemKey
	}
	return nil
}

func (v *Vault) Logout(email string, password string) error {
	masterPassword, err := v.getMasterPassword(email, password)
	if err != nil {
		return err
	}

	// Re encrypt url for each entry
	for i, entry := range v.Entries {
		if entry.Url.Encrypted {
			continue
		}
		url := entry.Url.Encrypt(masterPassword.S())
		v.Entries[i].Url = url
	}
	return nil
}

// Get master password
func (v Vault) getMasterPassword(email, password string) (EncryptedString, error) {
	var profile Profile
	for _, profile = range v.Profiles {
		if profile.Email == email {
			derivedKey := crypto.GetDerivedKey(password, v.Salt)
			return profile.MasterPassword.Decrypt(derivedKey), nil
		}
	}

	return EncryptedString{}, fmt.Errorf("no profile found for email %s", email)
}
