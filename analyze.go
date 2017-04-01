package devportal

import (
	"bytes"
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
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

var clonedRepos = make(map[string]string) // map of clone URL+branch to tmp dir
var clonedReposMu sync.Mutex

const clonedRepoCacheExpiry = 24 * time.Hour * 7

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
		os.Exit(0)
	}()
}

// allPluginInfos gets a list of plugin registrations discovered
// by static analysis at the given version of repo. If pullLatest
// is true, the latest repo will be pulled if it is already in
// the cache. If subfolder is specified, then only the package at
// that subfolder will be analyzed.
func allPluginInfos(repo, version, subfolder string, pullLatest bool) ([]Plugin, error) {
	var infos []Plugin

	// standardize input
	repo, version = strings.ToLower(repo), strings.ToLower(version)
	if !strings.HasPrefix(repo, "https://") {
		return infos, fmt.Errorf("clone URL must use https://, got: %s", repo)
	}

	// clone the repo (if needed)
	tmpdir, err := cloneRepo(pullLatest, repo, version)
	if err != nil {
		return infos, err
	}

	fset := token.NewFileSet()

	// get a list of all the packages in the repo or, if
	// specified, the specific subfolder only
	processDirPkgs := func(path string) error {
		dirpkgs, err := parser.ParseDir(fset, path, nil, 0)
		if err != nil {
			return err
		}
		var pkgs []*ast.Package
		for _, pkg := range dirpkgs {
			pkgs = append(pkgs, pkg)
		}

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
				return err
			}
			info.Type = regcall.PluginType
			infos = append(infos, info)
		}

		// analyzing large repos uses lots of memory,
		// and by some quirk of the Go 1.8 GC, calling
		// this manually does in fact reduce _some_
		// memory pressure (anywhere from 2-30 MB).
		debug.FreeOSMemory()

		return nil
	}

	if subfolder != "" {
		err = processDirPkgs(filepath.Join(tmpdir, subfolder))
	} else {
		err = filepath.Walk(tmpdir, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				return nil
			}
			return processDirPkgs(path)
		})
	}
	if err != nil {
		return infos, err
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
// directory. If pullLatest is true, it will update
// it with a git pull if repo@version is already in
// the cache.
//
// The return values are the temporary directory path
// and an error, if any.
func cloneRepo(pullLatest bool, repo, version string) (string, error) {
	cacheKey := strings.ToLower(repo) + "@" + strings.ToLower(version)

	clonedReposMu.Lock()
	tmpdir, ok := clonedRepos[cacheKey]
	clonedReposMu.Unlock()

	// depth of git clone and pull; 1 is fastest but may not pick up on
	// the tag/commit the user wants to deploy; 100+ may be slow if the
	// repo is large... choose something comfortable in the middle.
	const depth = "10"

	if !ok {
		// clone down this repo and cache it for future use

		var err error
		tmpdir, err = ioutil.TempDir("", "caddy_plugin_")
		if err != nil {
			return tmpdir, err
		}

		cmd := exec.Command("git", "clone", "--depth="+depth, repo, tmpdir)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		logBuf := new(bytes.Buffer)
		cmd.Stdout = logBuf
		cmd.Stderr = logBuf
		err = cmd.Run()
		if err != nil {
			os.RemoveAll(tmpdir)
			return tmpdir, fmt.Errorf("cloning repository: %v: >>>>>>>>>>>>>>> %s <<<<<<<<<<<<<<<", err, logBuf.String())
		}

		clonedReposMu.Lock()
		clonedRepos[cacheKey] = tmpdir
		clonedReposMu.Unlock()
		go func(tmpdir string, cacheKey string) {
			// wait a while, then delete this cached repo
			time.Sleep(clonedRepoCacheExpiry)
			clonedReposMu.Lock()
			delete(clonedRepos, cacheKey)
			clonedReposMu.Unlock()
			os.RemoveAll(tmpdir)
		}(tmpdir, cacheKey)
	} else if pullLatest {
		cmd := exec.Command("git", "pull", "--depth="+depth)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		logBuf := new(bytes.Buffer)
		cmd.Stdout = logBuf
		cmd.Stderr = logBuf
		cmd.Dir = tmpdir
		err := cmd.Run()
		if err != nil {
			return tmpdir, fmt.Errorf("pulling latest: %v: >>>>>>>>>>>>>>> %s <<<<<<<<<<<<<<<", err, logBuf.String())
		}
	}

	if version != "" {
		cmd := exec.Command("git", "checkout", version)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		logBuf := new(bytes.Buffer)
		cmd.Stdout = logBuf
		cmd.Stderr = logBuf
		cmd.Dir = tmpdir
		err := cmd.Run()
		if err != nil {
			return tmpdir, fmt.Errorf("git checkout: %v: >>>>>>>>>>>>>>> %s <<<<<<<<<<<<<<<", err, logBuf.String())
		}
	}

	return tmpdir, nil
}

// PluginCallExpr encapsulates some information about a function
// call in Go source code that is related to registering a plugin.
type PluginCallExpr struct {
	Package    *ast.Package
	File       *ast.File
	CallExpr   *ast.CallExpr
	PluginType PluginType
}
