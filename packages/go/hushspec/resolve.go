package hushspec

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// LoadedSpec pairs a parsed HushSpec with the canonical path it was loaded from.
type LoadedSpec struct {
	Source string
	Spec   *HushSpec
}

// ResolveLoader loads a HushSpec referenced by an extends field.
// reference is the extends value; from is the source of the referencing document.
type ResolveLoader func(reference string, from string) (*LoadedSpec, error)

// Resolve flattens the extends chain of a parsed HushSpec by repeatedly loading
// and merging parent documents via the provided loader.
func Resolve(spec *HushSpec, source string, loader ResolveLoader) (*HushSpec, error) {
	if loader == nil {
		loader = createCompositeLoader()
	}

	stack := make([]string, 0, 4)
	if source != "" {
		stack = append(stack, source)
	}
	return resolveInner(spec, source, loader, stack)
}

// ResolveFile loads a HushSpec from disk and flattens its extends chain.
func ResolveFile(path string) (*HushSpec, error) {
	source, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path %q: %w", path, err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize %q: %w", source, err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("failed to read HushSpec at %s: %w", source, err)
	}
	spec, err := Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HushSpec at %s: %w", source, err)
	}
	return Resolve(spec, source, createCompositeLoader())
}

// createCompositeLoader serves `builtin:<name>` references from the embedded
// rulesets and everything else from the filesystem (mirrors the Rust/TS
// resolvers). A bare name with no path separators or dots is tried as a
// builtin before falling back to the filesystem.
func createCompositeLoader() ResolveLoader {
	return func(reference string, from string) (*LoadedSpec, error) {
		if strings.HasPrefix(reference, "builtin:") {
			spec, ok := LoadBuiltin(reference)
			if !ok {
				return nil, fmt.Errorf("unknown builtin ruleset %q", reference)
			}
			return &LoadedSpec{Source: reference, Spec: spec}, nil
		}

		if !strings.ContainsAny(reference, `/\.`) {
			if spec, ok := LoadBuiltin(reference); ok {
				return &LoadedSpec{Source: "builtin:" + reference, Spec: spec}, nil
			}
		}

		return loadFromFilesystem(reference, from)
	}
}

func resolveInner(spec *HushSpec, source string, loader ResolveLoader, stack []string) (*HushSpec, error) {
	if spec == nil || spec.Extends == "" {
		return spec, nil
	}

	loaded, err := loader(spec.Extends, source)
	if err != nil {
		return nil, err
	}

	for index, entry := range stack {
		if entry == loaded.Source {
			cycle := append(slices.Clone(stack[index:]), loaded.Source)
			return nil, fmt.Errorf("circular extends detected: %s", joinChain(cycle))
		}
	}

	nextStack := append(stack, loaded.Source)
	parent, err := resolveInner(loaded.Spec, loaded.Source, loader, nextStack)
	if err != nil {
		return nil, err
	}

	return Merge(parent, spec), nil
}

func loadFromFilesystem(reference string, from string) (*LoadedSpec, error) {
	resolvedPath := reference
	if !filepath.IsAbs(reference) && from != "" {
		resolvedPath = filepath.Join(filepath.Dir(from), reference)
	}

	absPath, err := filepath.Abs(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path %q: %w", resolvedPath, err)
	}
	canonical, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize %q: %w", absPath, err)
	}
	content, err := os.ReadFile(canonical)
	if err != nil {
		return nil, fmt.Errorf("failed to read HushSpec at %s: %w", canonical, err)
	}
	spec, err := Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HushSpec at %s: %w", canonical, err)
	}
	return &LoadedSpec{Source: canonical, Spec: spec}, nil
}

func joinChain(chain []string) string {
	return strings.Join(chain, " -> ")
}
