package config

import "github.com/stefan-kiss/genkubessl/internal/storage"

type GlobalConfig struct {
	WriteDriver storage.StoreDrv
	ReadDriver  storage.StoreDrv
}
