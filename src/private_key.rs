use asn1_rs::{Any, Class, FromDer, Tag};
use pem::parse;
use pkcs8::PrivateKeyInfo;
use std::{fs, path::Path};

#[derive(Default)]
pub struct PrivKeyInfo {
    pub alg: Vec<u8>,
    pub alg_family: Vec<u8>,
    pub value: Vec<u8>,
}

impl PrivKeyInfo {
    pub fn build(file_name: &str) -> Option<PrivKeyInfo> {
        let mut priv_key_info = PrivKeyInfo::default();

        let path = Path::new(file_name);

        let key_buf = match fs::read(path) {
            Ok(key_buf) => key_buf,
            Err(_) => return None,
        };

        let pem = match parse(key_buf) {
            Ok(pem) => pem,
            Err(_) => return None,
        };

        let private_key = match PrivateKeyInfo::try_from(pem.contents()) {
            Ok(private_key) => private_key,
            Err(_) => return None,
        };

        priv_key_info.alg = private_key.algorithm.oid.as_bytes().to_vec();

        match Any::from_der(private_key.private_key) {
            Ok((_, any)) => PrivKeyInfo::get_der_any(any, &mut priv_key_info),
            Err(_) => return None,
        }

        if priv_key_info.alg.is_empty()
            || priv_key_info.alg_family.is_empty()
            || priv_key_info.value.is_empty()
        {
            return None;
        }

        Some(priv_key_info)
    }

    fn get_der_any(any: Any, ctx: &mut PrivKeyInfo) {
        match any.header.class() {
            Class::Universal => (),
            Class::ContextSpecific | Class::Application => {
                if let Ok((_, inner)) = Any::from_der(any.data) {
                    PrivKeyInfo::get_der_any(inner, ctx);
                }
                return;
            }
            _ => {
                return;
            }
        }
        match any.header.tag() {
            Tag::BitString => {
                let b = any.bitstring().unwrap();
                ctx.value = b.data.to_vec();
            }
            Tag::Integer => (),
            Tag::OctetString => (),
            Tag::Oid => {
                if let Ok(oid) = any.oid() {
                    ctx.alg_family = oid.as_bytes().to_vec();
                }
            }
            Tag::Sequence => {
                let seq = any.sequence().unwrap();
                for item in seq.der_iter::<Any, asn1_rs::Error>().flatten() {
                    PrivKeyInfo::get_der_any(item, ctx);
                }
            }
            _ => (),
        }
    }
}
