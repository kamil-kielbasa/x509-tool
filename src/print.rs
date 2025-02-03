use colorized::{colorize_println, Colors};
use der_parser::der::Tag;
use der_parser::oid::Oid;
use oid_registry::OidRegistry;
use std::borrow::Cow;
use std::convert::TryFrom;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;
use x509_parser::signature_algorithm::SignatureAlgorithm;

use crate::certificate::{X509DateTime, X509Info};
use crate::private_key::PrivKeyInfo;

pub fn print_raw_certificate(cert: &X509Info) {
    let chunk_size = 16;
    let indent = 0;

    // version
    colorize_println("Version", Colors::BlueBg);
    println!("{}", cert.version);

    // serial
    colorize_println("Serial", Colors::BlueBg);
    print_hex_colon(&cert.serial, chunk_size, indent);

    // siganture_alg
    colorize_println("Signature algorithm", Colors::BlueBg);
    print_hex_colon(&cert.sign_inf.alg_oid, chunk_size, indent);

    // issuer
    if !cert.issuer.c.is_empty() {
        colorize_println("Issuer - country", Colors::BlueBg);
        print_hex_colon(&cert.issuer.c, chunk_size, indent);
    }
    if !cert.issuer.o.is_empty() {
        colorize_println("Issuer - organization", Colors::BlueBg);
        print_hex_colon(&cert.issuer.o, chunk_size, indent);
    }
    if !cert.issuer.ou.is_empty() {
        colorize_println("Issuer - organization unit", Colors::BlueBg);
        print_hex_colon(&cert.issuer.ou, chunk_size, indent);
    }
    if !cert.issuer.cn.is_empty() {
        colorize_println("Issuer - common name", Colors::BlueBg);
        print_hex_colon(&cert.issuer.cn, chunk_size, indent);
    }
    if !cert.issuer.aeid.is_empty() {
        colorize_println("Issuer - AEID", Colors::BlueBg);
        print_hex_colon(&cert.issuer.aeid, chunk_size, indent);
    }

    // validity
    colorize_println("Validity - not before", Colors::BlueBg);
    print_time(&cert.not_before);

    colorize_println("Validity - not after", Colors::BlueBg);
    print_time(&cert.not_after);

    // subject
    if !cert.subject.c.is_empty() {
        colorize_println("Subject - country", Colors::BlueBg);
        print_hex_colon(&cert.subject.c, chunk_size, indent);
    }
    if !cert.subject.o.is_empty() {
        colorize_println("Subject - organization", Colors::BlueBg);
        print_hex_colon(&cert.subject.o, chunk_size, indent);
    }
    if !cert.subject.ou.is_empty() {
        colorize_println("Subject - organization unit", Colors::BlueBg);
        print_hex_colon(&cert.subject.ou, chunk_size, indent);
    }
    if !cert.subject.cn.is_empty() {
        colorize_println("Subject - common name", Colors::BlueBg);
        print_hex_colon(&cert.subject.cn, chunk_size, indent);
    }
    if !cert.subject.aeid.is_empty() {
        colorize_println("Subject - AEID", Colors::BlueBg);
        print_hex_colon(&cert.subject.aeid, chunk_size, indent);
    }

    // public key information
    colorize_println("Public key algorithm", Colors::BlueBg);
    print_hex_colon(&cert.pub_key_inf.alg_oid, chunk_size, indent);

    colorize_println("Public key algorithm family", Colors::BlueBg);
    print_hex_colon(&cert.pub_key_inf.alg_family_oid, chunk_size, indent);

    colorize_println("Public key value", Colors::BlueBg);
    print_hex_colon(&cert.pub_key_inf.value, chunk_size, indent);

    // extensions
    if !cert.ext.akid.is_empty() {
        colorize_println("Extension - authority key identifier", Colors::BlueBg);
        print_hex_colon(&cert.ext.akid, chunk_size, indent);
    }
    if !cert.ext.akid.is_empty() {
        colorize_println("Extension - subject key identifier", Colors::BlueBg);
        print_hex_colon(&cert.ext.skid, chunk_size, indent);
    }
    if !cert.ext.akid.is_empty() {
        colorize_println("Extension - certificate policy", Colors::BlueBg);
        print_hex_colon(&cert.ext.policy, chunk_size, indent);
    }
    if !cert.ext.akid.is_empty() {
        colorize_println("Extension - key usages", Colors::BlueBg);
        if cert.ext.usage.digital_signature {
            println!("digital signature");
        }
        if cert.ext.usage.non_repudiation {
            println!("non_repudiation");
        }
        if cert.ext.usage.key_encipherment {
            println!("key_encipherment");
        }
        if cert.ext.usage.data_encipherment {
            println!("data_encipherment");
        }
        if cert.ext.usage.key_agreement {
            println!("key_agreement");
        }
        if cert.ext.usage.key_cert_sign {
            println!("key_cert_sign");
        }
        if cert.ext.usage.crl_sign {
            println!("crl_sign");
        }
        if cert.ext.usage.encipher_only {
            println!("encipher_only");
        }
        if cert.ext.usage.decipher_only {
            println!("decipher_only");
        }
    }
}

pub fn print_pretty_certificate(cert: &X509Certificate) {
    println!("  Version: {}", cert.version());
    println!("  Serial: {}", cert.tbs_certificate.raw_serial_as_string());
    println!("  Subject: {}", cert.subject());
    println!("  Issuer: {}", cert.issuer());
    println!("  Validity:");
    println!("    NotBefore: {}", cert.validity().not_before);
    println!("    NotAfter:  {}", cert.validity().not_after);
    println!("    is_valid:  {}", cert.validity().is_valid());
    println!("  Subject Public Key Info:");
    print_pretty_public_key_info(cert.public_key());
    print_pretty_signature_algorithm(&cert.signature_algorithm, 4);

    println!("  Signature Value:");
    print_hex_colon(&cert.signature_value.data, 16, 6);

    println!("  Extensions:");
    for ext in cert.extensions() {
        print_pretty_extension(&ext.oid, ext);
    }
}

fn print_pretty_public_key_info(public_key: &SubjectPublicKeyInfo) {
    println!("    Public Key Algorithm:");
    print_x509_digest_algorithm(&public_key.algorithm, 6);
    if let Ok(PublicKey::EC(ec)) = public_key.parsed() {
        println!("    EC Public Key: ({} bit)", ec.key_size());
        print_hex_colon(ec.data(), 16, 6);
    }
}

fn print_pretty_signature_algorithm(signature_algorithm: &AlgorithmIdentifier, indent: usize) {
    match SignatureAlgorithm::try_from(signature_algorithm) {
        Ok(sig_alg) => {
            print!("  Signature Algorithm: ");
            if sig_alg == SignatureAlgorithm::ECDSA {
                println!("ECDSA")
            }
        }
        Err(e) => {
            eprintln!("Could not parse signature algorithm: {}", e);
            println!("  Signature Algorithm:");
            print_x509_digest_algorithm(signature_algorithm, indent);
        }
    }
}

fn print_pretty_extension(oid: &Oid, ext: &X509Extension) {
    println!(
        "    [crit:{} l:{}] {}: ",
        ext.critical,
        ext.value.len(),
        format_oid(oid)
    );
    match ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            println!("      X509v3 Authority Key Identifier");
            if let Some(key_id) = &aki.key_identifier {
                println!("        Key Identifier: {:x}", key_id);
            }
        }
        ParsedExtension::BasicConstraints(bc) => {
            println!("      X509v3 CA: {}", bc.ca);
        }
        ParsedExtension::KeyUsage(ku) => {
            println!("      X509v3 Key Usage: {}", ku);
        }
        ParsedExtension::SubjectKeyIdentifier(id) => {
            println!("      X509v3 Subject Key Identifier: {:x}", id);
        }
        ParsedExtension::CertificatePolicies(policies) => {
            println!("      X509v3 Certificate policies: {:x?}", policies);
        }
        _ => {}
    }
}

fn print_x509_digest_algorithm(alg: &AlgorithmIdentifier, level: usize) {
    println!(
        "{:indent$}Oid: {}",
        "",
        alg.algorithm.to_id_string(),
        indent = level
    );

    if let Some(parameter) = &alg.parameters {
        let s = match parameter.tag() {
            Tag::Oid => {
                let oid = parameter.as_oid().unwrap();
                format_oid(&oid)
            }
            _ => format!("{}", parameter.tag()),
        };
        println!("{:indent$}Parameter: {}", "", s, indent = level);
    }
}

fn format_oid(oid: &Oid) -> String {
    match oid2sn(oid, oid_registry()) {
        Ok(s) => s.to_owned(),
        _ => format!("{}", oid),
    }
}

fn print_time(time: &X509DateTime) {
    println!(
        "{}-{}-{} {}:{}:{}",
        time.year, time.month, time.day, time.hour, time.minuts, time.seconds
    );
}

fn print_hex_colon(vector: &[u8], chunk_size: usize, indent: usize) {
    for chunk in vector.chunks(chunk_size) {
        for _ in 0..indent {
            print!(" ");
        }
        for item in chunk {
            print!("{:02x}:", item);
        }
        println!();
    }
}

pub fn print_pretty_private_key(private_key: &PrivKeyInfo) {
    let level = 4;
    let chunk_size = 16;
    let registry = OidRegistry::default().with_crypto();

    println!("  Private key algorithm:");

    let alg = Oid::new(Cow::from(private_key.alg.as_slice()));
    println!("{:indent$}Oid: {}", "", alg.to_id_string(), indent = level);

    let oid_entry = registry.get(&alg);
    if let Some(oid_entry) = oid_entry {
        println!(
            "{:indent$}Short name: {}",
            "",
            oid_entry.sn(),
            indent = level
        );
        println!(
            "{:indent$}Description: {}",
            "",
            oid_entry.description(),
            indent = level
        );
    }

    println!("  Private key algorithm family:");

    let alg_family = Oid::new(Cow::from(private_key.alg_family.as_slice()));
    println!(
        "{:indent$}Oid: {}",
        "",
        alg_family.to_id_string(),
        indent = level
    );

    let oid_entry = registry.get(&alg_family);
    if let Some(oid_entry) = oid_entry {
        println!(
            "{:indent$}Short name: {}",
            "",
            oid_entry.sn(),
            indent = level
        );
        println!(
            "{:indent$}Description: {}",
            "",
            oid_entry.description(),
            indent = level
        );
    }

    println!("  Private key value:");
    print_hex_colon(&private_key.value, chunk_size, level);
}

pub fn print_raw_private_key(private_key: &PrivKeyInfo) {
    let indent = 0;
    let chunk_size = 16;

    // Private key algorithm
    colorize_println("Private key algorithm", Colors::BlueBg);
    print_hex_colon(&private_key.alg, chunk_size, indent);

    // Private key algorithm family
    colorize_println("Private key algorithm family", Colors::BlueBg);
    print_hex_colon(&private_key.alg_family, chunk_size, indent);

    // Private key algorithm family
    colorize_println("Private key value", Colors::BlueBg);
    print_hex_colon(&private_key.value, chunk_size, indent);
}
