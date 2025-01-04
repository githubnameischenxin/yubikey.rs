//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use der::{asn1::BitString, oid::ObjectIdentifier, pem::{Base64Decoder, LineEnding}, Decode, EncodePem};
use log::trace;
use nom::AsBytes;
use once_cell::sync::Lazy;
use openssl::x509::X509;
use rand_core::{OsRng, RngCore};
use rsa::{pkcs1v15, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512_256};
use signature::{hazmat::PrehashVerifier, SignerMut};
use sp_core::{ByteArray, Pair};
use std::{borrow::{Borrow, BorrowMut}, env, fs::File, io::{Read, Write}, str::FromStr, sync::Mutex, time::Duration};
use x509_cert::{builder::{Builder, RequestBuilder}, der::{referenced::OwnedToRef, Encode}, name::Name, request::{CertReq, CertReqInfo}, serial_number::SerialNumber, spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned}, time::Validity};
use yubikey::{
    certificate::{self, yubikey_signer::{self}, CertInfo, Certificate}, piv::{self, AlgorithmId, Key, ManagementSlotId, RetiredSlotId, SlotId}, Buffer, Error, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey
};

static YUBIKEY: Lazy<Mutex<YubiKey>> = Lazy::new(|| {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let yubikey = if let Ok(serial) = env::var("YUBIKEY_SERIAL") {
        let serial = Serial::from_str(&serial).unwrap();
        YubiKey::open_by_serial(serial).unwrap()
    } else {
        YubiKey::open().unwrap()
    };

    trace!("serial: {}", yubikey.serial());
    trace!("version: {}", yubikey.version());

    Mutex::new(yubikey)
});

//
// CCCID support
//

#[test]
#[ignore]
fn test_get_cccid() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    match yubikey.cccid() {
        Ok(cccid) => trace!("CCCID: {:?}", cccid),
        Err(Error::NotFound) => trace!("CCCID not found"),
        Err(err) => panic!("error getting CCCID: {:?}", err),
    }
}

//
// CHUID support
//

#[test]
#[ignore]
fn test_get_chuid() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    match yubikey.chuid() {
        Ok(chuid) => trace!("CHUID: {:?}", chuid),
        Err(Error::NotFound) => trace!("CHUID not found"),
        Err(err) => panic!("error getting CHUID: {:?}", err),
    }
}

//
// Device config support
//

#[test]
#[ignore]
fn test_get_config() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let config_result = yubikey.config();
    assert!(config_result.is_ok());
    trace!("config: {:?}", config_result.unwrap());
}

//
// Cryptographic key support
//

#[test]
#[ignore]
fn test_list_keys() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let keys_result = Key::list(&mut yubikey);
    assert!(keys_result.is_ok());
    trace!("keys: {:?}", keys_result.unwrap());
}

//
// PIN support
//

#[test]
#[ignore]
fn test_verify_pin() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"000000").is_err());
    assert!(yubikey.verify_pin(b"123456").is_ok());
}

//
// Management key support
//

#[cfg(feature = "untested")]
#[test]
#[ignore]
fn test_set_mgmkey() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    // Set a protected management key.
    assert!(MgmKey::generate().set_protected(&mut yubikey).is_ok());
    let protected = MgmKey::get_protected(&mut yubikey).unwrap();
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_ok());

    // Set a manual management key.
    let manual = MgmKey::generate();
    assert!(manual.set_manual(&mut yubikey, false).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_err());
    assert!(yubikey.authenticate(protected.clone()).is_err());
    assert!(yubikey.authenticate(manual.clone()).is_ok());

    // Set back to the default management key.
    assert!(MgmKey::set_default(&mut yubikey).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(protected).is_err());
    assert!(yubikey.authenticate(manual).is_err());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());
}

//
// Certificate support
//

fn generate_self_signed_cert<KT: yubikey_signer::KeyType>() -> Certificate {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        KT::ALGORITHM,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    // 0x80 0x00 ... (20bytes) is invalid because of high MSB (serial will keep the sign)
    // we'll limit ourselves to 19 bytes serial.
    let mut serial = [0u8; 19];
    OsRng.fill_bytes(&mut serial);
    let serial = SerialNumber::new(&serial[..]).expect("serial can't be more than 20 bytes long");
    let validity = Validity::from_now(Duration::new(500000, 0)).unwrap();

    // Generate a self-signed certificate for the new key.
    let cert_result = Certificate::generate_self_signed::<_, KT>(
        &mut yubikey,
        slot,
        serial,
        validity,
        Name::from_str("CN=testSubject").expect("parse name"),
        generated,
        |_builder| Ok(()),
    );

    assert!(cert_result.is_ok());
    let cert = cert_result.unwrap();
    trace!("cert: {:?}", cert);
    cert
}

#[test]
#[ignore]
fn generate_self_signed_rsa_cert() {
    let cert = generate_self_signed_cert::<yubikey_signer::YubiRsa<yubikey_signer::Rsa1024>>();

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = RsaPublicKey::try_from(cert.subject_pki()).expect("valid rsa key");
    let pubkey = pkcs1v15::VerifyingKey::<Sha256>::new(pubkey);

    let data = cert.cert.to_der().expect("serialize certificate");
    let tbs_cert_len = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;
    let msg = &data[4..8 + tbs_cert_len];
    let sig = pkcs1v15::Signature::try_from(&data[data.len() - 128..]).unwrap();
    let hash = Sha256::digest(msg);

    assert!(pubkey.verify_prehash(&hash, &sig).is_ok());
}

#[test]
#[ignore]
fn generate_self_signed_ec_cert() {
    let cert = generate_self_signed_cert::<p256::NistP256>();

    //
    // Verify that the certificate is signed correctly
    //

    let vk = p256::ecdsa::VerifyingKey::try_from(cert.subject_pki()).expect("ecdsa key expected");

    let data = cert.cert.to_der().expect("serialize certificate");
    let tbs_cert_len = data[6] as usize;
    let sig_algo_len = data[7 + tbs_cert_len + 1] as usize;
    let sig_start = 7 + tbs_cert_len + 2 + sig_algo_len + 3;
    let msg = &data[4..7 + tbs_cert_len];
    let sig = p256::ecdsa::Signature::from_der(&data[sig_start..]).unwrap();

    use p256::ecdsa::signature::Verifier;
    assert!(vk.verify(msg, &sig).is_ok());
}

#[test]
#[ignore]
fn test_slot_id_display() {
    assert_eq!(format!("{}", SlotId::Authentication), "Authentication");
    assert_eq!(format!("{}", SlotId::Signature), "Signature");
    assert_eq!(format!("{}", SlotId::KeyManagement), "KeyManagement");
    assert_eq!(
        format!("{}", SlotId::CardAuthentication),
        "CardAuthentication"
    );
    assert_eq!(format!("{}", SlotId::Attestation), "Attestation");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R1)), "R1");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R2)), "R2");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R3)), "R3");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R4)), "R4");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R5)), "R5");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R6)), "R6");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R7)), "R7");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R8)), "R8");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R9)), "R9");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R10)), "R10");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R11)), "R11");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R12)), "R12");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R13)), "R13");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R14)), "R14");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R15)), "R15");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R16)), "R16");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R17)), "R17");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R18)), "R18");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R19)), "R19");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R20)), "R20");

    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Pin)),
        "Pin"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Puk)),
        "Puk"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Management)),
        "Management"
    );
}

//
// Metadata
//

#[test]
#[ignore]
fn test_read_metadata() {
    let mut yubikey = YUBIKEY.lock().unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        AlgorithmId::EccP256,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    match piv::metadata(&mut yubikey, slot) {
        Ok(metadata) => assert_eq!(metadata.public, Some(generated)),
        Err(Error::NotSupported) => {
            // Some YubiKeys don't support metadata
            eprintln!("metadata not supported by this YubiKey");
        }
        Err(err) => panic!("{}", err),
    }
}

#[test]
#[ignore]
fn test_parse_cert_from_der() {
    let bob_der = std::fs::read("tests/assets/Bob.der").expect(".der file not found");
    let cert =
        certificate::Certificate::from_bytes(bob_der).expect("Failed to parse valid certificate");
    assert_eq!(
        cert.subject(),
        "CN=Bob",
        "Subject is {} should be CN=Bob",
        cert.subject()
    );
    assert_eq!(
        cert.issuer(),
        "CN=Ferdinand Linnenberg CA",
        "Issuer is {} should be {}",
        cert.issuer(),
        "CN=Ferdinand Linnenberg CA"
    );
}

//
// key generation ed25519
//

#[test]
#[ignore]
fn test_generate_key_ed25519() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R4);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        AlgorithmId::Ed25519,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    let pem = generated.to_pem(der::pem::LineEnding::LF).unwrap();
    trace!("{:?}", pem);
}

#[test]
#[ignore]
fn test_get_public_key() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"123456").is_ok());

    let slot = SlotId::KeyManagement;

    let public_key_info = match piv::metadata(&mut yubikey, slot) {
        Ok(metadata) => metadata.public,
        Err(Error::NotSupported) => {
            // Some YubiKeys don't support metadata
            eprintln!("metadata not supported by this YubiKey");
            None
        }
        Err(err) => panic!("{}", err),
    }.unwrap();
    let pem = public_key_info.to_pem(LineEnding::LF).unwrap();
    println!("============= PEM ===========");
    println!("pem: {}", pem);
    println!("=============================");
}

#[test]
#[ignore]
fn test_generate_csr_ed25519() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R4);

    let public_key = match piv::metadata(&mut yubikey, slot) {
        Ok(metadata) => metadata.public,
        Err(Error::NotSupported) => {
            eprintln!("metadata not supported by this YubiKey");
            None
        }
        Err(err) => panic!("{}", err),
    }.unwrap();

    // Generate a new key in the selected slot.
    let csr_pem = generate_csr(&mut yubikey, slot, public_key).unwrap();
    let _ = save_file(&csr_pem.as_bytes(), &format!("/Users/chenxin/projects/test/{}_csr.pem", slot)).unwrap();
    println!("{:?}", csr_pem);
}

fn generate_csr(yubikey: &mut YubiKey, slot: SlotId, subject_pki: SubjectPublicKeyInfoOwned) -> Result<String, Error> {
    
    let subject = Name::from_str(
        "C=CN,ST=BeiJing,L=BeiJing,O=Ferghana Group,OU=Ferghana Group IT Department,CN=ecaasospoc"
    ).unwrap();

    let version = Default::default();
    let public_key = subject_pki.to_owned();
    let attributes = Default::default();
    // let extension_req = x509_cert::request::ExtensionReq::default();
    let ed25519_oid = ObjectIdentifier::new_unwrap("1.3.101.112");
    let algorithm = AlgorithmIdentifierOwned {
        oid: ed25519_oid,
        parameters: None,
    };

    let cert_req_info = CertReqInfo {
        version,
        subject,
        public_key,
        attributes,
    };
    // cert_req_info.attributes.insert(extension_req.clone().try_into()?)?;
    let cert_req_info_der = cert_req_info.to_der().unwrap();
    let signature = sign_ed25519(yubikey, slot, &cert_req_info_der).unwrap().to_vec();
    let signature_bitstring = BitString::from_bytes(&signature).unwrap();

    let cert_req = CertReq {
        info: cert_req_info,
        algorithm,
        signature: signature_bitstring,
    };

    let csr_pem = cert_req.to_pem(der::pem::LineEnding::LF).unwrap();
    Ok(csr_pem)
}

fn save_file(content: &[u8], file_path: &str) -> std::io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(content)?;

    Ok(())
}

fn read_file(file_path: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    Ok(content)
}

#[test]
#[ignore]
fn test_import_cert() {
    let cert_pem = include_str!("/Users/chenxin/projects/test/R4_cert.pem");
    let start = cert_pem.find("-----BEGIN CERTIFICATE-----")
        .ok_or("Invalid PEM: no BEGIN CERTIFICATE header").unwrap()
        + "-----BEGIN CERTIFICATE-----".len();
    let end = cert_pem.find("-----END CERTIFICATE-----")
        .ok_or("Invalid PEM: no END CERTIFICATE footer").unwrap();
    let base64_data = &cert_pem[start..end].replace("\n", "").replace("\r", "");
    
    let mut decoder = Base64Decoder::new(&base64_data.as_bytes()).unwrap();
    let mut buf= Vec::new();
    let data = decoder.decode_to_end(&mut buf).unwrap();
    let cert = Certificate::from_bytes(data.to_vec()).unwrap();

    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R4);

    let _ = cert.write(&mut yubikey, slot, CertInfo::Uncompressed).unwrap();
}

#[test]
#[ignore]
fn test_sign_ed25519() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::KeyManagement;
    let msg = b"hello world asdfasdf asdkfjaskdfja sdfkajsdfk askdfja sdfkajsdfkajsdfkajsdfasdkfj ";
    
    let raw_in = msg;
    let signature = sign_ed25519(&mut yubikey, slot, raw_in.as_bytes()).unwrap();
    let signature_bytes = signature.to_vec();
    println!("signature bytes: {:?}", signature_bytes);
    println!("signature len: {:?}", signature_bytes.len());
    let _ = save_file(&signature_bytes, "/Users/chenxin/projects/test/9d_signature.bin");

    let cert_pem = include_str!("/Users/chenxin/projects/test/9d_cert.pem");
    let cert = openssl::x509::X509::from_pem(cert_pem.as_bytes()).unwrap();
    let public_key = cert.public_key().unwrap();
    let public_key_to_pem = public_key.public_key_to_pem().unwrap();
    let pub_pem = String::from_utf8(public_key_to_pem).unwrap();
    println!("pub_pem: {}", pub_pem);
    
    let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key).unwrap();
    println!("verify: {:?}", verifier.verify_oneshot(&signature_bytes, raw_in.as_bytes()).unwrap());

}

fn sign_ed25519(yubikey: &mut YubiKey, slot: SlotId, raw_in: &[u8]) -> Result<Buffer, Error> {
    assert!(yubikey.verify_pin(b"123456").is_ok());
    let signature = piv::sign_data(
        yubikey, 
        raw_in, 
        AlgorithmId::Ed25519, 
        slot
    );
    signature
}

/// 使用 polkadot sp-core 验证签名
#[test]
#[ignore]
fn test_verify_ed25519() {
    // let mut yubikey = YUBIKEY.lock().unwrap();
    // assert!(yubikey.verify_pin(b"123456").is_ok());
    // assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    // let slot = SlotId::KeyManagement;

    let msg = b"hello world asdfasdf asdkfjaskdfja sdfkajsdfk askdfja sdfkajsdfkajsdfkajsdfasdkfj ";

    // 读取签名
    let signature = read_file("/Users/chenxin/projects/test/9d_signature.bin").unwrap();

    // 读取证书的公钥
    let cert_pem = include_str!("/Users/chenxin/projects/test/9d_cert.pem");
    let cert = openssl::x509::X509::from_pem(cert_pem.as_bytes()).unwrap();
    let public_key = cert.public_key().unwrap();
    let public_key_to_pem = public_key.public_key_to_pem().unwrap();
    let pub_pem = String::from_utf8(public_key_to_pem).unwrap();
    println!("pub_pem: {}", pub_pem);

    // openssl 验证签名
    let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key).unwrap();
    println!("verify: {:?}", verifier.verify_oneshot(&signature, msg).unwrap());

    // polkadot sp-core 验证签名
    let pubkey = sp_core::ed25519::Public::from_slice(&public_key.raw_public_key().unwrap()).unwrap();
    let sig = sp_core::ed25519::Signature::from_slice(&signature).unwrap();
    
    let res = sp_core::ed25519::Pair::verify(&sig, msg, &pubkey);
    println!("polkadot verify: {:?}", res);

}

#[test]
#[ignore]
fn test_verify_ed25519_2() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(MgmKey::default()).is_ok());

    let slot = SlotId::KeyManagement;

    let msg = b"hello world";

    // 签名
    let raw_in = msg;
    let signature = sign_ed25519(&mut yubikey, slot, raw_in.as_bytes()).unwrap();
    let signature_bytes = signature.to_vec();


    // 读取公钥
    let public_key_info = match piv::metadata(&mut yubikey, slot) {
        Ok(metadata) => metadata.public,
        Err(Error::NotSupported) => {
            // Some YubiKeys don't support metadata
            eprintln!("metadata not supported by this YubiKey");
            None
        }
        Err(err) => panic!("{}", err),
    }.unwrap();

    // openssl 验证签名
    let public_key = openssl::pkey::PKey::public_key_from_der(&public_key_info.to_der().unwrap()).unwrap();
    let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key).unwrap();
    println!("verify: {:?}", verifier.verify_oneshot(&signature_bytes, msg).unwrap());
    
    // polkadot sp-core 验证签名
    let pubkey = sp_core::ed25519::Public::from_slice(&public_key_info.subject_public_key.as_bytes().unwrap()).unwrap();
    let sig = sp_core::ed25519::Signature::from_slice(&signature_bytes).unwrap();
    
    let res = sp_core::ed25519::Pair::verify(&sig, msg, &pubkey);
    println!("polkadot verify: {:?}", res);

}



