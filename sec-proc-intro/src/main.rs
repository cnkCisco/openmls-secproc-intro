use openmls::prelude::*;
use openmls_rust_crypto::{OpenMlsRustCrypto};


// A helper to create and store credentials.
fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Credential, CredentialError> {
    	let credential_bundle =
        	CredentialBundle::new(identity, credential_type, signature_algorithm, backend)?;
    	let credential_id =  credential_bundle.credential()
        	.signature_key()
        	.tls_serialize_detached()
        	.expect("Error serializing signature key.");
    // Store the credential bundle into the key store so OpenMLS has access
    // to it.
	    backend
        	.key_store()
        	.store(&credential_id, &credential_bundle)
        	.expect("An unexpected error occurred.");
    	Ok(credential_bundle.into_parts().0)
}

// A helper to create key package bundles.
fn generate_key_package_bundle(
    ciphersuites: &[Ciphersuite],
    credential: &Credential,
    backend: &impl OpenMlsCryptoProvider,
    ) -> Result<KeyPackage, KeyPackageBundleNewError> {
    // Fetch the credential bundle from the key store
    	let credential_id = credential
        	.signature_key()
        	.tls_serialize_detached()
        	.expect("Error serializing signature key.");
    	let credential_bundle = backend
        	.key_store()
        	.read(&credential_id)
        	.expect("An unexpected error occurred.");

    // Create the key package bundle
    	let key_package_bundle =
        	KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, vec![])?;

    // Store it in the key store
    	let key_package_id = key_package_bundle.key_package()
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.");
    	backend
		.key_store()
        	.store(key_package_id.value(), &key_package_bundle)
        	.expect("An unexpected error occurred.");
    Ok(key_package_bundle.into_parts().0)
}



fn main() {
        println!("Generate signed keys");
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let backend = &OpenMlsRustCrypto::default();
	// First they need credentials to identify them
	let alice_credential = generate_credential_bundle(
	    "Alice".into(),
    	     CredentialType::Basic,
    	     ciphersuite.signature_algorithm(),
    	     backend,
	)
	.expect("An unexpected error occurred.");

	let bob_credential = generate_credential_bundle(
    		"Bob".into(),
    		CredentialType::Basic,
    		ciphersuite.signature_algorithm(),
    		backend,
	)
	.expect("An unexpected error occurred.");

// Then they generate key packages to facilitate the asynchronous handshakes
// in MLS

// Generate KeyPackages
	let alice_key_package = generate_key_package_bundle(&[ciphersuite], &alice_credential, backend)
    	.expect("An unexpected error occurred.");

	let bob_key_package = generate_key_package_bundle(&[ciphersuite], &bob_credential, backend)
    	.expect("An unexpected error occurred.");

// Now Alice starts a new group ...
	let mut alice_group = MlsGroup::new(
		backend,
    		&MlsGroupConfig::default(),
    		GroupId::from_slice(b"teams-123"),
    		alice_key_package
        	.hash_ref(backend.crypto())
        	.expect("Could not hash KeyPackage.")
        	.as_slice(),
	)
	.expect("An unexpected error occurred.");

// ... and invites Bob
// The key package has to be retrieved from Bob
	let (mls_message_out, welcome) = alice_group
    	.add_members(backend, &[bob_key_package])
    	.expect("Could not add members.");

// Alice merges the pending commit that adds Bob.
	alice_group
   	.merge_pending_commit()
   	.expect("error merging pending commit");

// Now Bob can join the group.
	let mut bob_group = MlsGroup::new_from_welcome(
    	backend,
    	&MlsGroupConfig::default(),
    	welcome,
    // The public tree is need and transferred out of band.
    // It is also possible to use the [`RatchetTreeExtension`]
    	Some(alice_group.export_ratchet_tree()),
 	)
 	.expect("Error joining group from Welcome");
}
