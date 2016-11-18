package devportal

import (
	"fmt"
	"go/ast"
	"go/token"
	"log"
	"strings"
)

// PluginType contains information about a kind of plugin
// that is supported by this system.
type PluginType struct {
	ID            string // lower-case, underscore_spaces
	CategoryTitle string // human-readable title for plugin listings
	Description   string // concise description of what these plugins are/do

	// Name of package and function, as in a function call: "package.Func()"
	Package  string
	Function string

	// GetInfo takes a function call and is able to extract
	// the relevant information from it into a PluginInfo.
	// However, GetInfo is not able to label the PluginInfo
	// with the type of plugin this is (initialization loop).
	GetInfo func(*token.FileSet, PluginCallExpr) (PluginInfo, error) `json:"-"`
}

// pluginTypes is the list of plugin types that are
// understood by the system.
var pluginTypes = []PluginType{
	{
		ID:            "server_type",
		CategoryTitle: "Server Types",
		Description:   "Things Caddy can serve",
		Package:       "caddy",
		Function:      "RegisterServerType",
		GetInfo: func(fset *token.FileSet, call PluginCallExpr) (PluginInfo, error) {
			var info PluginInfo
			if len(call.CallExpr.Args) < 1 {
				return info, fmt.Errorf("TODO: not enough arguments...")
			}
			pname, err := staticEval(fset, call, call.CallExpr.Args[0])
			if err != nil {
				log.Println("ERROR:", err)
			}
			pluginName := pname
			info.Name = pluginName
			return info, nil
		},
	},
	{
		ID:            "generic",
		CategoryTitle: "Directives/Middleware",
		Description:   "Extra functionality with the Caddyfile",
		Package:       "caddy",
		Function:      "RegisterPlugin",
		GetInfo: func(fset *token.FileSet, call PluginCallExpr) (PluginInfo, error) {
			var info PluginInfo
			if len(call.CallExpr.Args) != 2 {
				return info, fmt.Errorf("TODO: not enough arguments...")
			}
			pname, err := staticEval(fset, call, call.CallExpr.Args[0])
			if err != nil {
				log.Println("ERROR:", err)
			}
			pluginName := strings.Trim(pname, "\"")
			elts := call.CallExpr.Args[1].(*ast.CompositeLit).Elts
			for _, elt := range elts {
				keyVal := elt.(*ast.KeyValueExpr)
				if keyVal.Key.(*ast.Ident).Name == "ServerType" {
					stname, err := staticEval(fset, call, keyVal.Value)
					if err != nil {
						log.Println("ERROR(2):", err)
					}
					pluginName = stname + "." + pluginName
				}
			}
			info.Name = pluginName
			return info, nil
		},
	},
	{
		ID:            "caddyfile_loader",
		CategoryTitle: "Caddyfile Loaders",
		Description:   "Ways to load the Caddyfile",
		Package:       "caddy",
		Function:      "RegisterCaddyfileLoader",
		GetInfo: func(fset *token.FileSet, call PluginCallExpr) (PluginInfo, error) {
			var info PluginInfo
			if len(call.CallExpr.Args) < 1 {
				return info, fmt.Errorf("TODO: not enough arguments...")
			}
			pname, err := staticEval(fset, call, call.CallExpr.Args[0])
			if err != nil {
				log.Println("ERROR:", err)
			}
			info.Name = pname
			return info, nil
		},
	},
	{
		ID:            "tls_dns_provider",
		CategoryTitle: "DNS Providers",
		Description:   "Obtain certificates using DNS",
		Package:       "caddytls",
		Function:      "RegisterDNSProvider",
		GetInfo: func(fset *token.FileSet, call PluginCallExpr) (PluginInfo, error) {
			var info PluginInfo
			if len(call.CallExpr.Args) < 1 {
				return info, fmt.Errorf("TODO: not enough arguments...")
			}
			pname, err := staticEval(fset, call, call.CallExpr.Args[0])
			if err != nil {
				log.Println("ERROR:", err)
			}
			info.Name = "tls.dns." + pname
			return info, nil
		},
	},
}
