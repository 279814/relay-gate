package probe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// P0-17 includes tests: accidentally retaining a fixture caller is enough to
// keep the second parser/network implementation alive after production moved.
func TestLegacyProbePathsHaveNoGoCallers(t *testing.T) {
	retired := map[string]bool{"buildProbeBody": true, "buildHeaders": true, "DefaultHeaderTemplate": true,
		"scanStream": true, "ClassifyHTTP": true, "ClassifyTransportErr": true, "NewUpstreamGate": true,
		"ProbeNow": true, "TransportFor": true, "BuildOutboundURL": true, "NewCostPersister": true,
		"classifyPayload": true, "classifySSEPrefix": true, "classifyJSONObject": true,
		"IsStructuredErrorPayload": true, "HasSemanticEvidence": true, "newStreamSemanticSniffer": true}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, path, nil, 0)
		if err != nil {
			return err
		}
		proxyImports := map[string]bool{}
		for _, spec := range file.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if importPath == "github.com/279814/relay-gate/internal/proxy" {
				alias := "proxy"
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				proxyImports[alias] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if decl, ok := node.(*ast.TypeSpec); ok && (decl.Name.Name == "streamErrorSniffer" || decl.Name.Name == "streamSemanticSniffer") {
				t.Errorf("retired response parser declared at %s", positions.Position(decl.Pos()))
			}
			if decl, ok := node.(*ast.FuncDecl); ok && decl.Name.Name == "InvalidateModelName" && file.Name.Name == "probe" && decl.Recv != nil {
				for _, receiver := range decl.Recv.List {
					if pointer, ok := receiver.Type.(*ast.StarExpr); ok {
						if name, ok := pointer.X.(*ast.Ident); ok && name.Name == "Scheduler" {
							t.Errorf("retired scheduler invalidator declared at %s", positions.Position(decl.Pos()))
						}
					}
				}
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
				if alias, ok := fun.X.(*ast.Ident); ok && name == "NewTransport" && proxyImports[alias.Name] {
					t.Errorf("retired proxy transport called at %s", positions.Position(call.Pos()))
				}
			}
			if retired[name] {
				t.Errorf("retired %s called at %s", name, positions.Position(call.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
