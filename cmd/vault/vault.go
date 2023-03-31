package vault

type Vault struct {
	Entries  []Entry   `json:"entries"`
	Profiles []Profile `json:"profiles"`
}

type Profile struct {
	Email                   string `json:"email"`
	EncryptedMasterPassword string `json:"encryptedMasterPassword"`
}

type Entry struct {
	Url                   string `json:"url"`
	EncryptedItemKey      string `json:"encryptedItemKey"`
	EncryptedItemPassword string `json:"encryptedItemPassword"`
}

func NewVault() Vault {
	return Vault{
		Entries:  []Entry{},
		Profiles: []Profile{},
	}
}
