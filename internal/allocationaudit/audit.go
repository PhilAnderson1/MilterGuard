// Package allocationaudit checks the reviewed allocation-effect boundary. It is
// diagnostic tooling, not part of the extraction path.
package allocationaudit

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
)

// Scan fingerprints complete production declarations, not merely calls whose
// names sound allocating. This covers wrappers, conversions, map assignments,
// closure/interface contexts, globals and excluded generators. A body change
// requires allocation-effect review even if a familiar helper name is retained.
// Tests/benchmarks remain in the census but are exempt from per-extraction rules.
func Scan(root string) (map[string]string, error) {
	out := make(map[string]string)
	files := token.NewFileSet()
	for _, dir := range []string{"internal/htmlextract", "internal/fork"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(files, path, nil, 0)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			names := make(map[string]int)
			for _, decl := range file.Decls {
				name := "<init>"
				if fn, ok := decl.(*ast.FuncDecl); ok {
					name = fn.Name.Name
					if fn.Recv != nil {
						var b bytes.Buffer
						printer.Fprint(&b, files, fn.Recv.List[0].Type)
						name = "(" + b.String() + ")." + name
					}
				}
				names[name]++
				var denied error
				ast.Inspect(decl, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Reserve" || sel.Sel.Name == "TryReserve") {
							denied = fmt.Errorf("%s: distributed accounting is forbidden", files.Position(call.Pos()))
						}
					}
					return true
				})
				if denied != nil {
					return denied
				}
				var body bytes.Buffer
				if err := printer.Fprint(&body, files, decl); err != nil {
					return err
				}
				out[fmt.Sprintf("%s::%s:%d", filepath.ToSlash(rel), name, names[name])] = fmt.Sprintf("%x", sha256.Sum256(body.Bytes()))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
