use convert_case::{Case, Casing};
use oid_registry::Oid;
use std::io::Error;
use std::io::ErrorKind;
use std::{fs::File, io::Write};

use crate::certificate::X509Info;
use crate::private_key::PrivKeyInfo;

pub fn render_certificate(file_name: &str, cert: &X509Info) -> Result<(), Error> {
    let mut file = File::create(format!("{file_name}.h"))?;

    match write_header(&mut file, file_name) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "cert", &cert.cert) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_oid(&mut file, file_name, "cert_fp_alg", &cert.hash_oid) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "cert_fp", &cert.hash) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_oid(&mut file, file_name, "sign_alg", &cert.sign_inf.alg_oid) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "sign", &cert.sign_inf.value) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "cert_tbs", &cert.tbs) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "version", cert.version) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "serial_nr", &cert.serial) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    if !cert.issuer.cn.is_empty() {
        match write_vector(&mut file, file_name, "issuer_cn", &cert.issuer.cn) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.issuer.o.is_empty() {
        match write_vector(&mut file, file_name, "issuer_o", &cert.issuer.o) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.issuer.ou.is_empty() {
        match write_vector(&mut file, file_name, "issuer_ou", &cert.issuer.ou) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.issuer.c.is_empty() {
        match write_vector(&mut file, file_name, "issuer_c", &cert.issuer.c) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.issuer.aeid.is_empty() {
        match write_vector(&mut file, file_name, "issuer_aeid", &cert.issuer.aeid) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    match write_value(
        &mut file,
        file_name,
        "not_before_year",
        cert.not_before.year,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(
        &mut file,
        file_name,
        "not_before_mon",
        cert.not_before.month,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "not_before_day", cert.not_before.day) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(
        &mut file,
        file_name,
        "not_before_hour",
        cert.not_before.hour,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(
        &mut file,
        file_name,
        "not_before_min",
        cert.not_before.minuts,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(
        &mut file,
        file_name,
        "not_before_sec",
        cert.not_before.seconds,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "not_after_year", cert.not_after.year) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "not_after_mon", cert.not_after.month) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "not_after_day", cert.not_after.day) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "not_after_hour", cert.not_after.hour) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(&mut file, file_name, "not_after_min", cert.not_after.minuts) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_value(
        &mut file,
        file_name,
        "not_after_sec",
        cert.not_after.seconds,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    if !cert.subject.cn.is_empty() {
        match write_vector(&mut file, file_name, "subject_cn", &cert.subject.cn) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.subject.o.is_empty() {
        match write_vector(&mut file, file_name, "subject_o", &cert.subject.o) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.subject.ou.is_empty() {
        match write_vector(&mut file, file_name, "subject_ou", &cert.subject.ou) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.subject.c.is_empty() {
        match write_vector(&mut file, file_name, "subject_c", &cert.subject.c) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.subject.aeid.is_empty() {
        match write_vector(&mut file, file_name, "subject_aeid", &cert.subject.aeid) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    match write_oid(
        &mut file,
        file_name,
        "pub_key_alg",
        &cert.pub_key_inf.alg_oid,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_oid(
        &mut file,
        file_name,
        "pub_key_alg_family",
        &cert.pub_key_inf.alg_family_oid,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "pub_key", &cert.pub_key_inf.value) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    if !cert.ext.akid.is_empty() {
        match write_vector(&mut file, file_name, "ext_akid", &cert.ext.akid) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.ext.skid.is_empty() {
        match write_vector(&mut file, file_name, "ext_skid", &cert.ext.skid) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.ext.policy.is_empty() {
        match write_vector(&mut file, file_name, "ext_policy", &cert.ext.policy) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    if !cert.ext.policy.is_empty() {
        match write_vector(&mut file, file_name, "ext_policy", &cert.ext.policy) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_digital_signature",
        cert.ext.usage.digital_signature,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_non_repudiation",
        cert.ext.usage.non_repudiation,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_key_encipherment",
        cert.ext.usage.key_encipherment,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_data_encipherment",
        cert.ext.usage.data_encipherment,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_key_agreement",
        cert.ext.usage.key_agreement,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_key_cert_sign",
        cert.ext.usage.key_cert_sign,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_crl_sign",
        cert.ext.usage.crl_sign,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_encipher_only",
        cert.ext.usage.encipher_only,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_boolean(
        &mut file,
        file_name,
        "ext_usage_decipher_only",
        cert.ext.usage.decipher_only,
    ) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    match write_end(&mut file, file_name) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    Ok(())
}

fn write_header(file: &mut File, file_name: &str) -> Result<(), Error> {
    let file_name_upper = format!("{}_H", file_name.to_case(Case::Upper).replace(" ", "_"));

    #[rustfmt::skip]
    let include_guard = format!(
        "#ifndef {file_name_upper}\n\
         #define {file_name_upper}\n\n"
    );

    match file.write_all(include_guard.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    #[rustfmt::skip]
    let headers =
        "#include <stdio.h>\n\
         #include <stddef.h>\n\
         #include <stdbool.h>\n\
         #include <psa/crypto.h>\n\n".to_string();

    match file.write_all(headers.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    Ok(())
}

fn write_end(file: &mut File, file_name: &str) -> Result<(), Error> {
    let file_name_upper = format!("{}_H", file_name.to_case(Case::Upper).replace(" ", "_"));

    #[rustfmt::skip]
    let end_include_guard = format!(
        "#endif /* {file_name_upper} */\n"
    );

    match file.write_all(end_include_guard.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    Ok(())
}

fn write_boolean(
    file: &mut File,
    file_name: &str,
    cert_part: &str,
    flag: bool,
) -> Result<(), Error> {
    #[rustfmt::skip]
    let boolean_definition = format!(
        "const bool {file_name}_{cert_part} = {flag};\n\n"
    );

    match file.write_all(boolean_definition.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    Ok(())
}

fn write_value(
    file: &mut File,
    file_name: &str,
    cert_part: &str,
    value: usize,
) -> Result<(), Error> {
    #[rustfmt::skip]
    let value_definition = format!(
        "const size_t {file_name}_{cert_part} = {value};\n\n"
    );

    match file.write_all(value_definition.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    Ok(())
}

fn write_vector(
    file: &mut File,
    file_name: &str,
    cert_part: &str,
    vector: &[u8],
) -> Result<(), Error> {
    #[rustfmt::skip]
    let array_declaration = format!(
        "const uint8_t {file_name}_{cert_part}[] = {{\n"
    );

    match file.write_all(array_declaration.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    let tab = "\t".to_string();
    let new_line = "\n".to_string();
    let chunk_size = 16;

    for chunk in vector.chunks(chunk_size) {
        match file.write_all(tab.as_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        for item in chunk {
            let byte = format!("0x{:02x}, ", item);

            match file.write_all(byte.as_bytes()) {
                Ok(_) => (),
                Err(e) => return Err(e),
            };
        }

        match file.write_all(new_line.as_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
    }

    #[rustfmt::skip]
    let array_end = "};\n\n".to_string();

    match file.write_all(array_end.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    Ok(())
}

fn write_oid(file: &mut File, file_name: &str, cert_part: &str, oid: &[u8]) -> Result<(), Error> {
    let new_oid = Oid::new(std::borrow::Cow::Borrowed(oid));

    if oid_registry::OID_NIST_HASH_SHA256 == new_oid {
        let hash_alg =
            format!("const psa_algorithm_t {file_name}_{cert_part} = PSA_ALG_SHA_256;\n\n");

        match file.write_all(hash_alg.as_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        return Ok(());
    }

    if oid_registry::OID_SIG_ECDSA_WITH_SHA256 == new_oid
        || oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY == new_oid
    {
        let ecdsa_sha_256 = format!(
            "const psa_algorithm_t {file_name}_{cert_part} = PSA_ALG_ECDSA(PSA_ALG_SHA_256);\n\n"
        );

        match file.write_all(ecdsa_sha_256.as_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        return Ok(());
    }

    if oid_registry::OID_EC_P256 == new_oid {
        let ec_p256 = format!(
            "const psa_key_type_t {file_name}_{cert_part} = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);\n\n"
        );

        match file.write_all(ec_p256.as_bytes()) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        return Ok(());
    }

    Err(Error::new(
        ErrorKind::Unsupported,
        "Not supported OID for PSA crypto API",
    ))
}

pub fn render_private_key(file_name: &str, priv_key_info: &PrivKeyInfo) -> Result<(), Error> {
    let mut file = File::create(format!("{file_name}.h"))?;

    match write_header(&mut file, file_name) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    match write_oid(&mut file, file_name, "priv_key_alg", &priv_key_info.alg) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    match write_oid(
        &mut file,
        file_name,
        "priv_key_alg_family",
        &priv_key_info.alg_family,
    ) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    match write_vector(&mut file, file_name, "priv_key_value", &priv_key_info.value) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    match write_end(&mut file, file_name) {
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    Ok(())
}
