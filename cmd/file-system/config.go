package file_system

type Config struct {
	FilePath string
}

const DEFAULT_FILEPATH = "vault.store.json"

func NewConfig() Config {
	return Config{
		FilePath: DEFAULT_FILEPATH,
	}
}
