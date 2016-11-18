package devportal

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var clonedRepos = make(map[string]string) // map of clone URL+branch to tmp dir
var clonedReposMu sync.Mutex

const clonedRepoCacheExpiry = 0 // TODO: 10 * time.Minute

func init() {
	// clean up temporary folders when closed
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		<-sigchan
		clonedReposMu.Lock()
		defer clonedReposMu.Unlock()
		for _, tmpdir := range clonedRepos {
			os.RemoveAll(tmpdir)
		}
		os.Exit(1)
	}()
}

// allPluginInfos gets a list of plugin registrations discovered
// by static analysis in the branch at repo. If allowCache is true,
// the repo will not be cloned anew if it was recently cloned.
func allPluginInfos(repo, branch string, allowCache bool) ([]PluginInfo, error) {
	var infos []PluginInfo

	// standardize input
	repo, branch = strings.ToLower(repo), strings.ToLower(branch)
	if !strings.HasPrefix(repo, "https://") {
		return infos, fmt.Errorf("clone URL must use https://")
	}
	if branch == "" {
		branch = "master"
	}

	// clone the repo (if needed)
	tmpdir, cacheKey, err := cloneRepo(allowCache, repo, branch)
	if err != nil {
		return infos, err
	}
	defer func(tmpdir string, allowCache bool, cacheKey string) {
		time.Sleep(clonedRepoCacheExpiry)
		if allowCache {
			clonedReposMu.Lock()
			delete(clonedRepos, cacheKey)
			clonedReposMu.Unlock()
		}
		os.RemoveAll(tmpdir)
	}(tmpdir, allowCache, cacheKey)

	fset := token.NewFileSet()

	// get a list of all the packages in the repo
	var pkgs []*ast.Package
	filepath.Walk(tmpdir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			return nil
		}
		dirpkgs, err := parser.ParseDir(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, pkg := range dirpkgs {
			pkgs = append(pkgs, pkg)
		}
		return nil
	})

	// find all function calls
	allFnCalls := findFunctions(pkgs, fset)

	// filter just the plugin registration calls
	var allRegCalls []PluginCallExpr
	for _, pluginType := range pluginTypes {
		allRegCalls = append(allRegCalls, filterPluginRegistrations(pluginType, allFnCalls)...)
	}

	// get information about each plugin registration
	for _, regcall := range allRegCalls {
		info, err := regcall.PluginType.GetInfo(fset, regcall)
		if err != nil {
			return infos, err
		}
		info.Type = regcall.PluginType
		infos = append(infos, info)
	}

	return infos, nil
}

// staticEval statically evaluates val in the context of the
// expression contained in expr. So if a function call in
// expr has some argument and you want to get the value,
// you would pass in that argument's expression as val.
func staticEval(fset *token.FileSet, expr PluginCallExpr, val ast.Expr) (string, error) {
	conf := types.Config{
		Importer: importer.Default(),
		Error:    func(err error) {}, // discard these errors since they are not useful to us
	}

	var info types.Info
	tpkg, _ := conf.Check(expr.Package.Name, fset, []*ast.File{expr.File}, &info)
	// discard error for same reason as above

	tav, err := types.Eval(fset, tpkg, expr.CallExpr.Pos(), types.ExprString(val))
	if err != nil {
		return "", fmt.Errorf("error in eval: %v", err)
	}

	return strings.Trim(tav.Value.String(), "\""), nil
}

// findFunctions iterates all the files in pkgs and pulls out all
// function calls.
func findFunctions(pkgs []*ast.Package, fset *token.FileSet) []PluginCallExpr {
	var calls []PluginCallExpr
	for _, pkg := range pkgs {
		for _, pkgfile := range pkg.Files {
			ast.Inspect(pkgfile, func(n ast.Node) bool {
				if fnCall, ok := n.(*ast.CallExpr); ok {
					calls = append(calls, PluginCallExpr{File: pkgfile, Package: pkg, CallExpr: fnCall})
				}
				return true
			})
		}
	}
	return calls
}

// filterPluginRegistrations iterates allCalls, looking for function
// calls that are plugin registrations recognized by plugin types
// described in this package. It labels the registration calls that
// it finds, so the returned list of calls contains information about
// the type of plugin they are associated with.
func filterPluginRegistrations(pluginType PluginType, allCalls []PluginCallExpr) []PluginCallExpr {
	var calls []PluginCallExpr
	for _, callexpr := range allCalls {
		if selexpr, ok := callexpr.CallExpr.Fun.(*ast.SelectorExpr); ok {
			if x, ok := selexpr.X.(*ast.Ident); ok {
				// TODO: Try x.Obj.Data.(*types.Package).Name for more package info...
				if x.Name == pluginType.Package && selexpr.Sel.Name == pluginType.Function {
					callexpr.PluginType = pluginType
					calls = append(calls, callexpr)
				}
			}
		}
	}
	return calls
}

// cloneRepo clones branch from repo into a temporary
// directory. If allowCache is true, it will not do a
// new clone if the repo+branch is already in the cache.
// This function creates a temporary directory that
// must be cleaned up by the caller! And if allowCache
// is true, then the caller must delete the entry
// from the cache, clonedRepos when the temporary
// directory is deleted.
//
// The return values are the temporary directory,
// the key for the cache map, and an error.
func cloneRepo(allowCache bool, repo, branch string) (string, string, error) {
	cacheKey := repo + branch

	clonedReposMu.Lock()
	tmpdir, ok := clonedRepos[cacheKey]
	clonedReposMu.Unlock()

	if !ok || !allowCache {
		var err error
		tmpdir, err = ioutil.TempDir("", "caddy_plugin_")
		if err != nil {
			return tmpdir, cacheKey, err
		}

		cmd := exec.Command("git", "clone", "-b", branch, "--depth=1", repo, tmpdir)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		cmd.Stdout = os.Stdout // TODO: Probably not needed
		cmd.Stderr = os.Stderr // TODO: Use log
		err = cmd.Run()
		if err != nil {
			return tmpdir, cacheKey, err
		}

		if allowCache {
			clonedReposMu.Lock()
			clonedRepos[cacheKey] = tmpdir
			clonedReposMu.Unlock()
		}
	}

	return tmpdir, cacheKey, nil
}

// PluginCallExpr encapsulates some information about a function
// call in Go source code that is related to registering a plugin.
type PluginCallExpr struct {
	Package    *ast.Package
	File       *ast.File
	CallExpr   *ast.CallExpr
	PluginType PluginType
}
