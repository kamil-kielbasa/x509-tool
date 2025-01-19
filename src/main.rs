use asn1_rs::{oid, Any, FromDer, Sequence, ToDer};
use clap::{Arg, Command};
use convert_case::{Case, Casing};
use oid_registry::OidRegistry;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Write};
use std::path::Path;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{ParsedExtension, X509Certificate};
use x509_parser::public_key::PublicKey;

fn main() -> std::io::Result<()> {
    let about = format!(
        "X.509 tool for operations like:\n\
                         - parse and print certificate on stdout\n\
                         - render certificate fields to static C-header"
    );

    let matches = Command::new("X.509 tool") // requires `cargo` feature
        .version("0.1")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about(about)
        .subcommand(
            Command::new("parse")
                .about("Parse and print given certificate")
                .arg(
                    Arg::new("path")
                        .short('p')
                        .long("path")
                        .required(true)
                        .help("Provides a path to certificate"),
                ),
        )
        .subcommand(
            Command::new("render")
                .about("render given certificate to C-header")
                .arg(
                    Arg::new("path")
                        .short('p')
                        .long("path")
                        .required(true)
                        .help("Provides a path to certificate"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("parse", sub_matches)) => {
            let cert_path = Path::new(sub_matches.get_one::<String>("path").unwrap());
            let cert = fs::read(cert_path).expect("Could not read certificate");

            let (_, pem) = parse_x509_pem(&cert).expect("Could not decode the PEM file");
            let (_, x509) =
                parse_x509_certificate(&pem.contents).expect("Could not parse the certificate");

            print_x509_info(&x509);

            Ok(())
        }
        Some(("render", sub_matches)) => {
            let cert_path = Path::new(sub_matches.get_one::<String>("path").unwrap());
            let cert = fs::read(cert_path).expect("Could not read certificate");

            let cert_name = cert_path
                .file_name()
                .expect("File name parse error")
                .to_str()
                .unwrap();
            let dot_idx = cert_name.chars().position(|c| c == '.').unwrap();
            let cert_name = &cert_name[..dot_idx].replace("-", "_");

            let (_, pem) = parse_x509_pem(&cert).expect("Could not decode the PEM file");
            let (_, x509) =
                parse_x509_certificate(&pem.contents).expect("Could not parse the certificate");

            let (_, seq_1) = Sequence::from_der(&pem.contents).unwrap();
            let (_, seq_2) = Sequence::from_der(&seq_1.content).unwrap();
            let tbs_len = pem.contents.len() - (seq_1.content.len() - seq_2.content.len());
            let tbs_buf = &seq_1.content[..tbs_len];

            write_x509_info(&cert_name, &x509, &pem.contents, &tbs_buf);

            Ok(())
        }
        _ => Err(Error::new(ErrorKind::InvalidInput, "Invalid input")),
    }
}

fn format_number_to_hex(b: &[u8], row_size: usize) -> Vec<String> {
    let mut v = Vec::with_capacity(1 + b.len() / row_size);
    for r in b.chunks(row_size) {
        let s = r.iter().fold(String::with_capacity(3 * r.len()), |a, b| {
            a + &format!("0x{:02x}, ", b)
        });
        v.push(s)
    }
    v
}

fn write_array(file: &mut File, file_name: &str, buffer: &[u8], name: &str) {
    file.write_all(format!("const uint8_t {file_name}_{name}[] = {{ ").as_bytes())
        .unwrap();
    file.write_all(b"\n").unwrap();
    for line in format_number_to_hex(buffer, 16) {
        file.write_all(b"\t").unwrap();
        file.write(line.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.write_all(format!("}};").as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
}

fn write_x509_info(cert_name: &str, x509: &X509Certificate, cert_buf: &[u8], tbs_buf: &[u8]) {
    let new_line_fmt = format!("\n");
    let mut file = File::create(format!("{cert_name}.h")).unwrap();

    let header_name_fmt = format!("{}_H", cert_name.to_case(Case::Upper).replace(" ", "_"));
    let include_guard_fmt = format!(
        "#ifndef {header_name_fmt}\n\
         #define {header_name_fmt}\n\n"
    );
    file.write(include_guard_fmt.as_bytes()).unwrap();

    let includes_fmt = format!(
        "#include <stdint.h>\n\
         #include <stddef.h>\n\n"
    );
    file.write(includes_fmt.as_bytes()).unwrap();

    // Certificate

    let cert_fmt = format!("/* Certificate. */\n");
    file.write(cert_fmt.as_bytes()).unwrap();
    write_array(&mut file, cert_name, cert_buf, "cert");
    file.write(new_line_fmt.as_bytes()).unwrap();

    // Certificate hash SHA-256
    let mut hasher = Sha256::new();
    hasher.update(cert_buf);
    let hash = hasher.finalize();

    let cert_fmt = format!("/* Certificate fingerprint with SHA-2-256. */\n");
    file.write(cert_fmt.as_bytes()).unwrap();
    write_array(&mut file, cert_name, &hash, "cert_fp");
    file.write(new_line_fmt.as_bytes()).unwrap();

    // Basic certificate fields

    let cert_fields_fmt = format!("/* Basic Certificate Fields: */\n");
    file.write(cert_fields_fmt.as_bytes()).unwrap();
    file.write(new_line_fmt.as_bytes()).unwrap();

    // TBSCertificate

    let tbs_fmt = format!("/* tbsCertificate. */\n");
    file.write(tbs_fmt.as_bytes()).unwrap();
    write_array(&mut file, cert_name, tbs_buf, "tbs");
    file.write(new_line_fmt.as_bytes()).unwrap();

    // Signature Algorithm

    let oid = &x509.signature_algorithm.algorithm;
    if oid!(1.2.840 .10045 .4 .3 .2) == *oid {
        let sign_alg_fmt = format!("/* signatureAlgorithm. */\n");
        file.write(sign_alg_fmt.as_bytes()).unwrap();
        let sig_fmt =
            format!("const size_t {cert_name}_sign_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);\n");
        file.write(sig_fmt.as_bytes()).unwrap();
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    // Signature Value

    let (_, sign_seq) = Any::from_der(&x509.signature_value.data).expect("Parsing failure.");
    let (_, sign_int1) = Any::from_der(&sign_seq.data).expect("Parsing failure.");
    let offset = ToDer::to_der_len(&sign_int1.data).unwrap();
    let (_, sign_int2) = Any::from_der(&sign_seq.data[offset..]).expect("Parsing failure.");

    let x = match sign_int1.data.len() {
        32 => sign_int1.data,
        33 => &sign_int1.data[1..],
        _ => panic!("Not supported yet."),
    };

    let y = match sign_int2.data.len() {
        32 => sign_int2.data,
        33 => &sign_int2.data[1..],
        _ => panic!("Not supported yet."),
    };

    let sign_value_fmt = format!("/* signatureValue. */\n");
    file.write(sign_value_fmt.as_bytes()).unwrap();
    let res: Vec<u8> = [x, y].concat();
    write_array(&mut file, cert_name, res.as_slice(), "sign_value");
    file.write(new_line_fmt.as_bytes()).unwrap();

    // TBSCertificate

    let tbs_cert_fmt = format!("/* TBSCertificate: */\n");
    file.write(tbs_cert_fmt.as_bytes()).unwrap();
    file.write(new_line_fmt.as_bytes()).unwrap();

    // Version

    let version = x509.version();

    if version.0 < 3 {
        let ver_fmt = format!("/* Version. */\n");
        file.write(ver_fmt.as_bytes()).unwrap();
        file.write_all(format!("const size_t {cert_name}_ver = {{ ").as_bytes())
            .unwrap();
        write!(&mut file, "{}", version.0 + 1).expect("Error");
        file.write_all(format!(" }};").as_bytes()).unwrap();
        file.write(new_line_fmt.as_bytes()).unwrap();
    } else {
        println!("  Version: INVALID({})", version.0);
    }

    file.write_all(b"\n").unwrap();

    // Serial number

    let serial_fmt = format!("/* Serial Number. */\n");
    file.write(serial_fmt.as_bytes()).unwrap();
    write_array(&mut file, cert_name, x509.raw_serial(), "serial_nr");
    file.write(new_line_fmt.as_bytes()).unwrap();

    // Issuer

    for item in x509.issuer().iter_common_name() {
        let issuer_fmt = format!("/* Issuer - Common Name (CN). */\n");
        file.write(issuer_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "issuer_cn");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.issuer().iter_organization() {
        let issuer_fmt = format!("/* Issuer - Organization (O). */\n");
        file.write(issuer_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "issuer_o");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.issuer().iter_organizational_unit() {
        let issuer_fmt = format!("/* Issuer - Organization Unit (OU). */\n");
        file.write(issuer_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "issuer_ou");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.issuer().iter_country() {
        let issuer_fmt = format!("/* Issuer - Counter (C). */\n");
        file.write(issuer_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "issuer_c");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.issuer().iter_by_oid(&oid!(1.3.6 .1 .4 .1 .37734 .1)) {
        let issuer_fmt = format!("/* Issuer - AEID. */\n");
        file.write(issuer_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "issuer_aeid");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    // Validity - From

    let val_from_fmt = format!("/* Validity - From. */\n");
    file.write(val_from_fmt.as_bytes()).unwrap();

    let not_before = x509.validity.not_before.to_datetime();

    let year_fmt = format!(
        "const size_t {cert_name}_validity_from_year = {};\n",
        not_before.year()
    );
    file.write(year_fmt.as_bytes()).unwrap();

    let mon_fmt = format!(
        "const size_t {cert_name}_validity_from_mon = {};\n",
        not_before.month() as u8
    );
    file.write(mon_fmt.as_bytes()).unwrap();

    let day_fmt = format!(
        "const size_t {cert_name}_validity_from_day = {};\n",
        not_before.day()
    );
    file.write(day_fmt.as_bytes()).unwrap();

    let hour_fmt = format!(
        "const size_t {cert_name}_validity_from_hour = {};\n",
        not_before.hour()
    );
    file.write(hour_fmt.as_bytes()).unwrap();

    let min_fmt = format!(
        "const size_t {cert_name}_validity_from_min = {};\n",
        not_before.minute()
    );
    file.write(min_fmt.as_bytes()).unwrap();

    let sec_fmt = format!(
        "const size_t {cert_name}_validity_from_sec = {};\n",
        not_before.second()
    );
    file.write(sec_fmt.as_bytes()).unwrap();

    file.write(new_line_fmt.as_bytes()).unwrap();

    // Validity - To

    let not_after = x509.validity.not_after.to_datetime();

    let val_to_fmt = format!("/* Validity - To. */\n");
    file.write(val_to_fmt.as_bytes()).unwrap();

    let year_fmt = format!(
        "const size_t {cert_name}_validity_to_year = {};\n",
        not_after.year()
    );
    file.write(year_fmt.as_bytes()).unwrap();

    let mon_fmt = format!(
        "const size_t {cert_name}_validity_to_mon = {};\n",
        not_after.month() as u8
    );
    file.write(mon_fmt.as_bytes()).unwrap();

    let day_fmt = format!(
        "const size_t {cert_name}_validity_to_day = {};\n",
        not_after.day()
    );
    file.write(day_fmt.as_bytes()).unwrap();

    let hour_fmt = format!(
        "const size_t {cert_name}_validity_to_hour = {};\n",
        not_after.hour()
    );
    file.write(hour_fmt.as_bytes()).unwrap();

    let min_fmt = format!(
        "const size_t {cert_name}_validity_to_min = {};\n",
        not_after.minute()
    );
    file.write(min_fmt.as_bytes()).unwrap();

    let sec_fmt = format!(
        "const size_t {cert_name}_validity_to_sec = {};\n",
        not_after.second()
    );
    file.write(sec_fmt.as_bytes()).unwrap();

    // Subject

    file.write(new_line_fmt.as_bytes()).unwrap();

    for item in x509.subject().iter_organization() {
        let subject_fmt = format!("/* Subject - Organization (O). */\n");
        file.write(subject_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "subject_o");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.subject().iter_organizational_unit() {
        let subject_fmt = format!("/* Subject - Organization Unit (OU). */\n");
        file.write(subject_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "subject_ou");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.subject().iter_common_name() {
        let subject_fmt = format!("/* Subject - Common Name (CN). */\n");
        file.write(subject_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "subject_cn");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.subject().iter_country() {
        let subject_fmt = format!("/* Subject - Country (C). */\n");
        file.write(subject_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "subject_c");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    for item in x509.subject().iter_by_oid(&oid!(1.3.6 .1 .4 .1 .37734 .1)) {
        let subject_fmt = format!("/* Subject - AEID. */\n");
        file.write(subject_fmt.as_bytes()).unwrap();
        write_array(&mut file, cert_name, item.as_slice(), "subject_aeid");
        file.write(new_line_fmt.as_bytes()).unwrap();
    }

    // Public key info

    if oid!(1.2.840 .10045 .2 .1) == x509.public_key().algorithm.algorithm {
        let pub_key_fmt = format!("/* Subject Public Key Info - Algorithm. */");
        file.write(pub_key_fmt.as_bytes()).unwrap();
        file.write(new_line_fmt.as_bytes()).unwrap();
        let pub_key_alg_fmt =
            format!("const size_t {cert_name}_pub_key_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);\n");
        file.write(pub_key_alg_fmt.as_bytes()).unwrap();
    }

    if let Some(params) = &x509.public_key().algorithm.parameters {
        let oid = params.as_oid().unwrap();

        if oid!(1.2.840 .10045 .3 .1 .7) == oid {
            let pub_key_alg_family_fmt = format!("const size_t {cert_name}_pub_key_alg_family = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);\n");
            file.write(pub_key_alg_family_fmt.as_bytes()).unwrap();
        }
    }

    file.write(new_line_fmt.as_bytes()).unwrap();

    match x509.public_key().parsed() {
        Ok(PublicKey::EC(ec)) => {
            let pub_key_fmt = format!("/* Subject Public Key Info - Value. */");
            file.write(pub_key_fmt.as_bytes()).unwrap();
            file.write(b"\n").unwrap();
            write_array(&mut file, cert_name, ec.data(), "public_key_value");
            file.write(new_line_fmt.as_bytes()).unwrap();
        }
        _ => (),
    }

    // Extensions

    let ext_fmt = format!("/* Certificate extensions: */");
    file.write(ext_fmt.as_bytes()).unwrap();
    file.write(new_line_fmt.as_bytes()).unwrap();
    file.write(new_line_fmt.as_bytes()).unwrap();

    for ext in x509.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(akid) => {
                let ext_fmt = format!("/* Authority Key Identifier. */");
                file.write(ext_fmt.as_bytes()).unwrap();
                file.write(new_line_fmt.as_bytes()).unwrap();
                write_array(
                    &mut file,
                    cert_name,
                    akid.key_identifier.clone().unwrap().0,
                    "ext_akid",
                );
                file.write(new_line_fmt.as_bytes()).unwrap();
            }

            ParsedExtension::SubjectKeyIdentifier(skid) => {
                let ext_fmt = format!("/* Subject Key Identifier. */");
                file.write(ext_fmt.as_bytes()).unwrap();
                file.write(new_line_fmt.as_bytes()).unwrap();
                write_array(&mut file, cert_name, skid.0, "ext_skid");
                file.write(new_line_fmt.as_bytes()).unwrap();
            }

            ParsedExtension::CertificatePolicies(policies) => {
                let mut iter = policies.iter();
                let policy = iter.next().unwrap();

                let ext_fmt = format!("/* Certificate policies. */");
                file.write(ext_fmt.as_bytes()).unwrap();
                file.write(new_line_fmt.as_bytes()).unwrap();
                write_array(
                    &mut file,
                    cert_name,
                    policy.policy_id.as_bytes(),
                    "ext_policy",
                );
                file.write(new_line_fmt.as_bytes()).unwrap();
            }

            _ => (),
        }
    }

    let include_guard_fmt = format!("#endif /* {header_name_fmt} */\n");
    file.write(include_guard_fmt.as_bytes()).unwrap();
}

fn print_x509_info(x509: &X509Certificate) {
    let version = x509.version();

    if version.0 < 3 {
        println!("  Version: {}", version);
    } else {
        println!("  Version: INVALID({})", version.0);
    }

    println!("  Serial: {}", x509.tbs_certificate.raw_serial_as_string());
    println!("  Subject: {}", x509.subject());
    println!("  Issuer: {}", x509.issuer());
    println!("  Validity:");
    println!("    IsValid:   {}", x509.validity().is_valid());
    println!("    NotBefore: {}", x509.validity().not_before);
    println!("    NotBefore: {}", x509.validity().not_after);

    let registry = OidRegistry::default().with_all_crypto();

    println!("  Subject Public Key Info:");
    let oid = &x509.public_key().algorithm.algorithm;
    let oid_entry = registry.get(&x509.public_key().algorithm.algorithm);

    if let Some(oid_entry) = oid_entry {
        println!(
            "    {} ({}, {})",
            oid.to_id_string(),
            oid_entry.sn(),
            oid_entry.description()
        );
    }

    if let Some(params) = &x509.public_key().algorithm.parameters {
        let oid = params.as_oid().unwrap();
        let oid_entry = registry.get(&oid).unwrap();
        println!(
            "    {} ({}, {})",
            oid.to_id_string(),
            oid_entry.sn(),
            oid_entry.description()
        );
    }

    match x509.public_key().parsed() {
        Ok(PublicKey::EC(ec)) => {
            println!("    EC Public Key: ({} bit)", ec.key_size());
            for line in format_number_to_hex_with_colon(ec.data(), 16) {
                println!("      {}", line);
            }
        }
        _ => (),
    }

    println!("  Signature algorithm: ");
    let oid = &x509.signature_algorithm.algorithm;
    let oid_entry = registry.get(&x509.signature_algorithm.algorithm);

    if let Some(oid_entry) = oid_entry {
        println!(
            "    {} ({}, {})",
            oid.to_id_string(),
            oid_entry.sn(),
            oid_entry.description()
        );
    }

    println!("  Signature Value:");
    let (_, sign_seq) = Any::from_der(&x509.signature_value.data).expect("Parsing failure.");
    let (_, sign_int1) = Any::from_der(&sign_seq.data).expect("Parsing failure.");
    let offset = ToDer::to_der_len(&sign_int1.data).unwrap();
    let (_, sign_int2) = Any::from_der(&sign_seq.data[offset..]).expect("Parsing failure.");

    let res: Vec<u8> = [sign_int1.data, sign_int2.data].concat();
    for l in format_number_to_hex_with_colon(&res.as_slice(), 16) {
        println!("      {}", l);
    }

    println!("  Extensions:");
    for ext in x509.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(akid) => {
                println!("    Authority Key Identifier:");
                for l in
                    format_number_to_hex_with_colon(&akid.key_identifier.clone().unwrap().0, 16)
                {
                    println!("      {}", l);
                }
            }

            ParsedExtension::SubjectKeyIdentifier(skid) => {
                println!("    Subject Key Identifier:");
                for l in format_number_to_hex_with_colon(&skid.0, 16) {
                    println!("      {}", l);
                }
            }

            ParsedExtension::CertificatePolicies(policies) => {
                println!("    Certificate Policies:");
                for item in policies.iter() {
                    for l in format_number_to_hex_with_colon(item.policy_id.as_bytes(), 16) {
                        println!("      {}", l);
                    }
                }
            }

            _ => (),
        }
    }
}

fn format_number_to_hex_with_colon(b: &[u8], row_size: usize) -> Vec<String> {
    let mut v = Vec::with_capacity(1 + b.len() / row_size);
    for r in b.chunks(row_size) {
        let s = r.iter().fold(String::with_capacity(3 * r.len()), |a, b| {
            a + &format!("{:02x}:", b)
        });
        v.push(s)
    }
    v
}
