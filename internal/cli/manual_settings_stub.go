//go:build !linux || !cgo || !gsettings

package cli

import "github.com/lamb-systems/dottie/internal/service"

func manualGNOMESettings() service.SettingsPort { return nil }
