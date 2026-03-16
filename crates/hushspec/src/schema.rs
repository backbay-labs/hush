pub use crate::generated_models::{HushSpec, MergeStrategy};

impl HushSpec {
    /// Parse a YAML string into a `HushSpec`.
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Serialize this spec back to a YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}
