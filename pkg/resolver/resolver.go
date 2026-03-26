package resolver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/julietsecurity/abom/pkg/model"
	"github.com/julietsecurity/abom/pkg/parser"
)

// Options configures the resolver.
type Options struct {
	MaxDepth  int
	Token     string
	NoNetwork bool
	Quiet     bool
	LocalRoot string
}

// Resolver recursively resolves transitive action dependencies.
type Resolver struct {
	fetcher  ContentFetcher
	cache    *FileCache
	opts     Options
	seen     map[string]bool        // cycle detection (current stack)
	memo     map[string][]*model.ActionRef // memoization of resolved deps
}

// New creates a resolver with the given options.
func New(opts Options) (*Resolver, error) {
	r := &Resolver{
		opts: opts,
		seen: make(map[string]bool),
		memo: make(map[string][]*model.ActionRef),
	}

	if !opts.NoNetwork {
		r.fetcher = NewGitHubFetcher(opts.Token)
		cache, err := NewFileCache()
		if err != nil {
			return nil, fmt.Errorf("initializing cache: %w", err)
		}
		r.cache = cache
	}

	return r, nil
}

// ResolveWorkflows resolves all transitive dependencies for all workflows.
func (r *Resolver) ResolveWorkflows(workflows []*model.Workflow) error {
	if r.opts.NoNetwork {
		return nil
	}

	for _, wf := range workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action != nil {
					r.resolveAction(step.Action, 0)
				}
			}
		}
	}
	return nil
}

func (r *Resolver) resolveAction(ref *model.ActionRef, depth int) {
	if depth >= r.opts.MaxDepth {
		ref.ResolveError = fmt.Sprintf("max depth %d reached", r.opts.MaxDepth)
		return
	}

	// Docker and local actions with no network — skip or handle specially
	switch ref.ActionType {
	case model.ActionTypeDocker:
		return
	case model.ActionTypeLocal:
		r.resolveLocalAction(ref, depth)
		return
	}

	key := ref.Raw

	// Cycle detection
	if r.seen[key] {
		ref.ResolveError = "cycle detected"
		return
	}

	// Memoization
	if deps, ok := r.memo[key]; ok {
		ref.Dependencies = deps
		return
	}

	r.seen[key] = true
	defer func() { delete(r.seen, key) }()

	var content []byte
	var err error

	switch ref.ActionType {
	case model.ActionTypeStandard, model.ActionTypeSubdirectory:
		content, err = r.fetchAction(ref)
	case model.ActionTypeReusable:
		content, err = r.fetchWorkflow(ref)
	}

	if err != nil {
		ref.ResolveError = err.Error()
		return
	}

	var deps []*model.ActionRef

	switch ref.ActionType {
	case model.ActionTypeStandard, model.ActionTypeSubdirectory:
		result, parseErr := parser.ParseActionFileFull(content)
		if parseErr != nil {
			ref.ResolveError = fmt.Sprintf("parsing action file: %v", parseErr)
			return
		}
		deps = result.Deps
		ref.DetectedTools = result.DetectedTools
	case model.ActionTypeReusable:
		wf, parseErr := parser.ParseWorkflow(content, ref.Raw)
		if parseErr != nil {
			ref.ResolveError = fmt.Sprintf("parsing reusable workflow: %v", parseErr)
			return
		}
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action != nil {
					deps = append(deps, step.Action)
				}
			}
		}
	}

	ref.Dependencies = deps
	r.memo[key] = deps

	if !r.opts.Quiet && len(deps) > 0 {
		fmt.Fprintf(os.Stderr, "  Resolved %s: %d transitive dep(s)\n", formatRef(ref), len(deps))
	}

	// Recursively resolve dependencies
	for _, dep := range deps {
		r.resolveAction(dep, depth+1)
	}
}

func (r *Resolver) resolveLocalAction(ref *model.ActionRef, depth int) {
	if r.opts.LocalRoot == "" {
		ref.ResolveError = "no local root set for resolving local actions"
		return
	}

	// Prevent path traversal outside the repo root
	cleanRoot := filepath.Clean(r.opts.LocalRoot)
	candidate := filepath.Clean(filepath.Join(cleanRoot, ref.Path))
	if !strings.HasPrefix(candidate, cleanRoot+string(filepath.Separator)) && candidate != cleanRoot {
		ref.ResolveError = fmt.Sprintf("path traversal blocked: %s escapes repo root", ref.Path)
		return
	}

	// Try action.yml then action.yaml
	actionPath := filepath.Join(candidate, "action.yml")
	content, err := os.ReadFile(actionPath)
	if err != nil {
		actionPath = filepath.Join(candidate, "action.yaml")
		content, err = os.ReadFile(actionPath)
		if err != nil {
			ref.ResolveError = fmt.Sprintf("local action not found: %s", ref.Path)
			return
		}
	}

	deps, err := parser.ParseActionFile(content)
	if err != nil {
		ref.ResolveError = fmt.Sprintf("parsing local action: %v", err)
		return
	}

	ref.Dependencies = deps
	for _, dep := range deps {
		r.resolveAction(dep, depth+1)
	}
}

func (r *Resolver) fetchAction(ref *model.ActionRef) ([]byte, error) {
	isSHA := ref.RefType == model.RefTypeSHA

	// Try cache first
	if r.cache != nil {
		if content, err := r.cache.Get(ref.Owner, ref.Repo, ref.Ref, ref.Path, isSHA); err == nil {
			return content, nil
		}
	}

	if r.fetcher == nil {
		return nil, fmt.Errorf("network disabled, cannot fetch %s", ref.Raw)
	}

	content, err := r.fetcher.FetchActionYAML(ref.Owner, ref.Repo, ref.Ref, ref.Path)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if r.cache != nil {
		_ = r.cache.Put(ref.Owner, ref.Repo, ref.Ref, ref.Path, content)
	}

	return content, nil
}

func (r *Resolver) fetchWorkflow(ref *model.ActionRef) ([]byte, error) {
	isSHA := ref.RefType == model.RefTypeSHA

	if r.cache != nil {
		if content, err := r.cache.Get(ref.Owner, ref.Repo, ref.Ref, ref.Path, isSHA); err == nil {
			return content, nil
		}
	}

	if r.fetcher == nil {
		return nil, fmt.Errorf("network disabled, cannot fetch %s", ref.Raw)
	}

	content, err := r.fetcher.FetchWorkflowFile(ref.Owner, ref.Repo, ref.Ref, ref.Path)
	if err != nil {
		return nil, err
	}

	if r.cache != nil {
		_ = r.cache.Put(ref.Owner, ref.Repo, ref.Ref, ref.Path, content)
	}

	return content, nil
}

func formatRef(ref *model.ActionRef) string {
	if ref.Owner != "" && ref.Repo != "" {
		return ref.Owner + "/" + ref.Repo + "@" + ref.Ref
	}
	return ref.Raw
}
