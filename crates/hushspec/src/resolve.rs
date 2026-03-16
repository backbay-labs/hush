use crate::{HushSpec, merge};
use std::fs;
use std::path::{Path, PathBuf};

/// A loaded HushSpec document plus its canonical source identifier.
#[derive(Clone, Debug)]
pub struct LoadedSpec {
    pub source: String,
    pub spec: HushSpec,
}

/// Errors raised while resolving `extends`.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to read HushSpec document at {path}: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse HushSpec document at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("circular extends detected: {chain}")]
    Cycle { chain: String },
}

/// Resolve a parsed spec using a caller-provided loader.
pub fn resolve_with_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    let mut stack = Vec::new();
    if let Some(source) = source {
        stack.push(source.to_string());
    }
    resolve_inner(spec, source, loader, &mut stack)
}

/// Resolve a HushSpec document from disk using filesystem-relative `extends`.
pub fn resolve_from_path(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    let path = canonical_path(path.as_ref())?;
    let spec = load_spec_from_file(&path)?;
    resolve_with_loader(&spec, Some(&path.to_string_lossy()), &load_from_filesystem)
}

fn resolve_inner<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
    stack: &mut Vec<String>,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    let Some(reference) = spec.extends.as_deref() else {
        return Ok(spec.clone());
    };

    let loaded = loader(reference, source)?;
    if let Some(index) = stack.iter().position(|entry| entry == &loaded.source) {
        let mut cycle = stack[index..].to_vec();
        cycle.push(loaded.source);
        return Err(ResolveError::Cycle {
            chain: cycle.join(" -> "),
        });
    }

    stack.push(loaded.source.clone());
    let resolved_parent = resolve_inner(&loaded.spec, Some(&loaded.source), loader, stack)?;
    stack.pop();
    Ok(merge(&resolved_parent, spec))
}

fn load_from_filesystem(reference: &str, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
    let path = resolve_reference_path(reference, from);
    let canonical = canonical_path(&path)?;
    let spec = load_spec_from_file(&canonical)?;
    Ok(LoadedSpec {
        source: canonical.to_string_lossy().into_owned(),
        spec,
    })
}

fn resolve_reference_path(reference: &str, from: Option<&str>) -> PathBuf {
    let candidate = PathBuf::from(reference);
    if candidate.is_absolute() {
        return candidate;
    }

    match from
        .map(PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
    {
        Some(parent) => parent.join(candidate),
        None => candidate,
    }
}

fn canonical_path(path: &Path) -> Result<PathBuf, ResolveError> {
    fs::canonicalize(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn load_spec_from_file(path: &Path) -> Result<HushSpec, ResolveError> {
    let content = fs::read_to_string(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    HushSpec::parse(&content).map_err(|error| ResolveError::Parse {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}
