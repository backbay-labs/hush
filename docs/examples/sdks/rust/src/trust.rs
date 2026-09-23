use hushspec::signing::{
    Keyring, SignOptions, VerifyOptions, generate_keypair, sign_policy, verify_policy,
};
use hushspec::{EvaluationAction, FileProvider, HushGuard, HushSpec, PolicyProvider};

pub fn check_trust(path: &str, resolved: &HushSpec) -> Result<(), Box<dyn std::error::Error>> {
    // Fresh demonstration key, discarded at process exit.
    let (private, public) = generate_keypair();
    let ring = Keyring::from_verifying_keys([public])?;
    let envelope = sign_policy(resolved, &private, &SignOptions::default())?;
    verify_policy(&envelope, resolved, &ring, &VerifyOptions::default())?;
    let (_, other) = generate_keypair();
    let wrong = Keyring::from_verifying_keys([other])?;
    assert!(verify_policy(&envelope, resolved, &wrong, &VerifyOptions::default()).is_err());
    let provider = FileProvider::new(path);
    let guard = HushGuard::from_resolution(provider.load()?)?;
    assert!(
        !guard
            .check(&EvaluationAction {
                action_type: "tool_call".into(),
                target: Some("deploy".into()),
                ..Default::default()
            })
            .allowed()
    );
    Ok(())
}
