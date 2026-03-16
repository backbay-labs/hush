package hushspec

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadedSpec carries a loaded HushSpec document plus its canonical source ID.
type LoadedSpec struct {
	Source string
	Spec   *HushSpec
}

// ResolveLoader loads a referenced HushSpec and returns its canonical source.
type ResolveLoader func(reference string, from string) (*LoadedSpec, error)

// Resolve resolves a parsed HushSpec document using the provided loader.
func Resolve(spec *HushSpec, source string, loader ResolveLoader) (*HushSpec, error) {
	if loader == nil {
		loader = loadFromFilesystem
	}

	stack := make([]string, 0, 4)
	if source != "" {
		stack = append(stack, source)
	}
	return resolveInner(spec, source, loader, stack)
}

// ResolveFile loads and resolves a HushSpec document from disk.
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
	return Resolve(spec, source, loadFromFilesystem)
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
			cycle := append(append([]string{}, stack[index:]...), loaded.Source)
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
	if !filepath.IsAbs(reference) {
		if from != "" {
			resolvedPath = filepath.Join(filepath.Dir(from), reference)
		}
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
	switch len(chain) {
	case 0:
		return ""
	case 1:
		return chain[0]
	default:
		result := chain[0]
		for _, item := range chain[1:] {
			result += " -> " + item
		}
		return result
	}
}
