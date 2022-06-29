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

fn generate_authorized_subscribers_list()-> Vec<SignaturePublicKey> {
	let mut auth_keys = Vec::new();
	return auth_keys;
}

fn extract_public_key_from_key_package(key_package: &KeyPackage)->SignaturePublicKey {
	let credential = key_package.credential();
	credential.signature_key().clone()
}

//Verify if public key of user is an authorized one
fn is_authorized_user(auth_keys: &Vec<SignaturePublicKey>, other_pk: &SignaturePublicKey) -> bool {
	auth_keys.contains(other_pk)
}

fn main() {
        println!("Generate signed keys");
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let backend = &OpenMlsRustCrypto::default();

	let mut authorized_subscribers_keys = generate_authorized_subscribers_list();
	// First they need credentials to identify them
	let alice_credential = generate_credential_bundle(
	    "Alice".into(),
    	     CredentialType::Basic,
    	     ciphersuite.signature_algorithm(),
    	     backend,
	)
	.expect("An unexpected error occurred.");
	let alice_pk = alice_credential.signature_key().clone();
	authorized_subscribers_keys.push(alice_pk);
	// Generate KeyPackages
        let alice_key_package = generate_key_package_bundle(&[ciphersuite], &alice_credential, backend)
        .expect("An unexpected error occurred.");



	//Bob'sKeyPackage is generated here for testing. Ideally, this should come from UI
	let bob_credential = generate_credential_bundle(
    		"Bob".into(),
    		CredentialType::Basic,
    		ciphersuite.signature_algorithm(),
    		backend,
	)
	.expect("An unexpected error occurred.");
	let bob_pk = bob_credential.signature_key().clone();
	authorized_subscribers_keys.push(bob_pk);
	let bob_key_package = generate_key_package_bundle(&[ciphersuite], &bob_credential, backend)
    	.expect("An unexpected error occurred.");


//Extract bob's public key from his keypackage and verify
	let bob_public_key = extract_public_key_from_key_package(&bob_key_package);
	let is_bob_authorized =	is_authorized_user(&authorized_subscribers_keys, &bob_public_key);
	match is_bob_authorized {
		true => println!("Authorized user"),
		false => println!("Unauthorized user"),
	}
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
