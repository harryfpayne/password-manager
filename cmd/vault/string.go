package vault

import (
	"encoding/hex"
	"encoding/json"
	"github.com/harryfpayne/password-manager/cmd/crypto"
)

var _ json.Marshaler = (*EncryptedString)(nil)
var _ json.Unmarshaler = (*EncryptedString)(nil)

type EncryptedString struct {
	e         []byte // Encrypted string
	s         string
	Encrypted bool
}

func NewEncryptedString(s string) EncryptedString {
	return EncryptedString{
		s:         s,
		Encrypted: false,
	}
}

func (s EncryptedString) S() string {
	if s.Encrypted {
		panic("tried to get unencrypted string")
	}
	return s.s
}

func (s EncryptedString) Decrypt(password string) EncryptedString {
	if !s.Encrypted {
		return s
	}
	d := crypto.Decrypt(s.e, password)
	return EncryptedString{
		s:         d,
		Encrypted: false,
	}
}

func (s EncryptedString) Encrypt(password string) EncryptedString {
	if s.Encrypted {
		return s
	}
	e := crypto.Encrypt(s.s, password)
	return EncryptedString{
		e:         e,
		Encrypted: true,
	}
}

func (u EncryptedString) MarshalJSON() ([]byte, error) {
	if !u.Encrypted {
		panic("tried to store unencrypted string")
	}

	return []byte("\"" + hex.EncodeToString(u.e) + "\""), nil
}

func (u *EncryptedString) UnmarshalJSON(data []byte) error {
	u.Encrypted = true

	u.e = make([]byte, hex.DecodedLen(len(data[1:len(data)-1])))
	_, err := hex.Decode(u.e, data[1:len(data)-1])
	return err
}
