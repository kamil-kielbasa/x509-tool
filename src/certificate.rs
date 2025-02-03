use asn1_rs::{oid, Any, FromDer, Oid, Sequence, ToDer};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{ParsedExtension, X509Certificate};
use x509_parser::public_key::PublicKey;

#[rustfmt::skip]
const AEID_OID: Oid = oid!(1.3.6.1.4.1.37734.1);

#[derive(Default)]
pub struct X509Issuer {
    pub cn: Vec<u8>,
    pub o: Vec<u8>,
    pub ou: Vec<u8>,
    pub c: Vec<u8>,
    pub aeid: Vec<u8>,
}

#[derive(Default)]
pub struct X509Subject {
    pub cn: Vec<u8>,
    pub o: Vec<u8>,
    pub ou: Vec<u8>,
    pub c: Vec<u8>,
    pub aeid: Vec<u8>,
}

#[derive(Default)]
pub struct X509PublicKeyInfo {
    pub alg_oid: Vec<u8>,
    pub alg_family_oid: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Default)]
pub struct X509SignInfo {
    pub alg_oid: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Default)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

#[derive(Default)]
pub struct X509Extensions {
    pub akid: Vec<u8>,
    pub skid: Vec<u8>,
    pub policy: Vec<u8>,
    pub usage: KeyUsage,
}

#[derive(Default)]
pub struct X509DateTime {
    pub year: usize,
    pub month: usize,
    pub day: usize,
    pub hour: usize,
    pub minuts: usize,
    pub seconds: usize,
}

#[derive(Default)]
pub struct X509Info {
    pub cert: Vec<u8>,
    pub hash: Vec<u8>,
    pub hash_oid: Vec<u8>,
    pub tbs: Vec<u8>,
    pub sign_inf: X509SignInfo,
    pub version: usize,
    pub serial: Vec<u8>,
    pub issuer: X509Issuer,
    pub not_before: X509DateTime,
    pub not_after: X509DateTime,
    pub subject: X509Subject,
    pub pub_key_inf: X509PublicKeyInfo,
    pub ext: X509Extensions,
}

pub enum ErrorKind {
    AlgorithmNotSupported,
    AsnInvalidData,
    Other,
}

impl X509Info {
    pub fn build(file_name: &str) -> Option<X509Info> {
        let mut x509_info = X509Info::default();

        let path = Path::new(file_name);

        let cert_buf = match fs::read(path) {
            Ok(cert_buf) => cert_buf,
            Err(_) => return None,
        };

        let pem = match parse_x509_pem(&cert_buf) {
            Ok((_, pem)) => pem,
            Err(_) => return None,
        };

        let x509 = match parse_x509_certificate(&pem.contents) {
            Ok((_, x509)) => x509,
            Err(_) => return None,
        };

        x509_info.fill_cert(&pem.contents);
        x509_info.fill_cert_hash(&pem.contents);

        if x509_info.fill_tbs(&pem.contents).is_err() {
            return None;
        }

        if x509_info.fill_sign_inf(&x509).is_err() {
            return None;
        }

        x509_info.fill_version(&x509);
        x509_info.fill_serial_nr(&x509);
        x509_info.fill_issuer(&x509);
        x509_info.fill_validity(&x509);
        x509_info.fill_subject(&x509);

        if x509_info.fill_public_key_info(&x509).is_err() {
            return None;
        }

        if x509_info.fill_extensions(&x509).is_err() {
            return None;
        }

        Some(x509_info)
    }

    fn fill_cert(&mut self, cert: &[u8]) {
        self.cert = cert.to_vec();
    }

    fn fill_cert_hash(&mut self, cert: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(cert);
        let hash = hasher.finalize();

        self.hash = hash.to_vec();
        self.hash_oid = oid_registry::OID_NIST_HASH_SHA256.as_bytes().to_vec();
    }

    fn fill_tbs(&mut self, cert: &[u8]) -> Result<(), ErrorKind> {
        let seq_1 = match Sequence::from_der(cert) {
            Ok((_, seq)) => seq,
            Err(_) => return Err(ErrorKind::AsnInvalidData),
        };

        let seq_2 = match Sequence::from_der(&seq_1.content) {
            Ok((_, seq)) => seq,
            Err(_) => return Err(ErrorKind::AsnInvalidData),
        };

        let tbs_len = cert.len() - (seq_1.content.len() - seq_2.content.len());
        let tbs_buf = &seq_1.content[..tbs_len];

        self.tbs = tbs_buf.to_vec();

        Ok(())
    }

    fn fill_sign_inf(&mut self, x509: &X509Certificate) -> Result<(), ErrorKind> {
        if oid_registry::OID_SIG_ECDSA_WITH_SHA256 != x509.signature_algorithm.algorithm {
            return Err(ErrorKind::AlgorithmNotSupported);
        }

        self.sign_inf.alg_oid = x509.signature_algorithm.algorithm.as_bytes().to_vec();

        let sign_seq = match Any::from_der(&x509.signature_value.data) {
            Ok((_, seq)) => seq,
            Err(_) => return Err(ErrorKind::AsnInvalidData),
        };

        let sign_int1 = match Any::from_der(sign_seq.data) {
            Ok((_, int)) => int,
            Err(_) => return Err(ErrorKind::AsnInvalidData),
        };

        let offset = match ToDer::to_der_len(&sign_int1.data) {
            Ok(len) => len,
            Err(_) => return Err(ErrorKind::AsnInvalidData),
        };

        let sign_int2 = match Any::from_der(&sign_seq.data[offset..]) {
            Ok((_, int)) => int,
            Err(_) => return Err(ErrorKind::AsnInvalidData),
        };

        let x_coord = match sign_int1.data.len() {
            32 => sign_int1.data,
            33 => &sign_int1.data[1..],
            _ => return Err(ErrorKind::AsnInvalidData),
        };

        let y_coord = match sign_int2.data.len() {
            32 => sign_int2.data,
            33 => &sign_int2.data[1..],
            _ => return Err(ErrorKind::AsnInvalidData),
        };

        self.sign_inf.value = [x_coord, y_coord].concat();

        Ok(())
    }

    fn fill_version(&mut self, x509: &X509Certificate) {
        self.version = x509.version().0 as usize + 1;
    }

    fn fill_serial_nr(&mut self, x509: &X509Certificate) {
        self.serial = x509.raw_serial().to_vec();
    }

    fn fill_issuer(&mut self, x509: &X509Certificate) {
        if let Some(iter) = x509.issuer().iter_common_name().next() {
            self.issuer.cn = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.issuer().iter_organization().next() {
            self.issuer.o = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.issuer().iter_organizational_unit().next() {
            self.issuer.ou = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.issuer().iter_country().next() {
            self.issuer.c = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.issuer().iter_by_oid(&AEID_OID).next() {
            self.issuer.aeid = iter.as_slice().to_vec();
        }
    }

    fn fill_validity(&mut self, x509: &X509Certificate) {
        let not_before = x509.validity.not_before.to_datetime();

        self.not_before.year = not_before.year() as usize;
        self.not_before.month = not_before.month() as usize;
        self.not_before.day = not_before.day() as usize;
        self.not_before.hour = not_before.hour() as usize;
        self.not_before.minuts = not_before.minute() as usize;
        self.not_before.seconds = not_before.second() as usize;

        let not_after = x509.validity.not_after.to_datetime();

        self.not_after.year = not_after.year() as usize;
        self.not_after.month = not_after.month() as usize;
        self.not_after.day = not_after.day() as usize;
        self.not_after.hour = not_after.hour() as usize;
        self.not_after.minuts = not_after.minute() as usize;
        self.not_after.seconds = not_after.second() as usize;
    }

    fn fill_subject(&mut self, x509: &X509Certificate) {
        if let Some(iter) = x509.subject().iter_common_name().next() {
            self.subject.cn = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.subject().iter_organization().next() {
            self.subject.o = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.subject().iter_organizational_unit().next() {
            self.subject.ou = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.subject().iter_country().next() {
            self.subject.c = iter.as_slice().to_vec();
        }

        if let Some(iter) = x509.subject().iter_by_oid(&AEID_OID).next() {
            self.subject.aeid = iter.as_slice().to_vec();
        }
    }

    fn fill_public_key_info(&mut self, x509: &X509Certificate) -> Result<(), ErrorKind> {
        if oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY != x509.public_key().algorithm.algorithm {
            return Err(ErrorKind::AlgorithmNotSupported);
        }

        self.pub_key_inf.alg_oid = oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY.as_bytes().to_vec();

        let params = match &x509.public_key().algorithm.parameters {
            Some(params) => params,
            None => return Err(ErrorKind::AlgorithmNotSupported),
        };
        let public_key_alg_oid = match params.as_oid() {
            Ok(oid) => oid,
            Err(_) => return Err(ErrorKind::AlgorithmNotSupported),
        };

        if oid_registry::OID_EC_P256 != public_key_alg_oid {
            return Err(ErrorKind::AlgorithmNotSupported);
        }

        self.pub_key_inf.alg_family_oid = oid_registry::OID_EC_P256.as_bytes().to_vec();

        match x509.public_key().parsed() {
            Ok(PublicKey::EC(ec)) => self.pub_key_inf.value = ec.data().to_vec(),
            _ => return Err(ErrorKind::AlgorithmNotSupported),
        }

        Ok(())
    }

    fn fill_extensions(&mut self, x509: &X509Certificate) -> Result<(), ErrorKind> {
        for ext in x509.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(akid) => match &akid.key_identifier {
                    Some(value) => self.ext.akid = value.0.to_vec(),
                    None => return Err(ErrorKind::Other),
                },
                ParsedExtension::SubjectKeyIdentifier(skid) => {
                    self.ext.skid = skid.0.to_vec();
                }
                ParsedExtension::CertificatePolicies(policy) => match policy.iter().next() {
                    Some(value) => match value.policy_id.to_der_vec() {
                        Ok(vec) => self.ext.policy = vec.clone(),
                        Err(_) => return Err(ErrorKind::Other),
                    },
                    None => return Err(ErrorKind::Other),
                },
                ParsedExtension::KeyUsage(usage) => {
                    self.ext.usage.digital_signature = usage.digital_signature();
                    self.ext.usage.non_repudiation = usage.non_repudiation();
                    self.ext.usage.key_encipherment = usage.key_encipherment();
                    self.ext.usage.data_encipherment = usage.data_encipherment();
                    self.ext.usage.key_agreement = usage.key_agreement();
                    self.ext.usage.key_cert_sign = usage.key_cert_sign();
                    self.ext.usage.crl_sign = usage.crl_sign();
                    self.ext.usage.encipher_only = usage.encipher_only();
                    self.ext.usage.decipher_only = usage.decipher_only();
                }
                _ => (),
            }
        }

        Ok(())
    }
}
