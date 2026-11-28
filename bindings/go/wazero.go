package strig

import "github.com/tetratelabs/wazero"

func moduleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().WithName("")
}
