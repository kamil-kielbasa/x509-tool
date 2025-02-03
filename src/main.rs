use clap::{Arg, Command};
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::Path;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

mod certificate;
mod print;
mod private_key;
mod render;

fn main() -> Result<(), Error> {
    #[rustfmt::skip]
    let about =
        "X.509 tool for operations like:\n\
         - parse and print certificate on stdout\n\
         - render certificate fields to static C-header".to_string();

    let matches = Command::new("X.509 tool")
        .version("0.1")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about(about)
        .subcommand(
            Command::new("print")
                .about("Print given certificate or private key")
                .arg(
                    Arg::new("certificate")
                        .short('c')
                        .long("certificate")
                        .required(false)
                        .help("Provides a path to X.509 certificate encoded as PEM"),
                )
                .arg(
                    Arg::new("private_key")
                        .short('k')
                        .long("private_key")
                        .required(false)
                        .help("Provides a path to PKCS#8 private key encoded as PEM"),
                )
                .arg(
                    Arg::new("raw")
                        .short('r')
                        .long("raw")
                        .required(false)
                        .action(clap::ArgAction::SetTrue)
                        .help("Print in raw format"),
                ),
        )
        .subcommand(
            Command::new("render")
                .about("Render given certificate or private key to C-header")
                .arg(
                    Arg::new("certificate")
                        .short('c')
                        .long("certificate")
                        .required(false)
                        .help("Provides a path to X.509 certificate encoded as PEM"),
                )
                .arg(
                    Arg::new("private_key")
                        .short('k')
                        .long("private_key")
                        .required(false)
                        .help("Provides a path to PKCS#8 private key encoded as PEM"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("print", sub_matches)) => {
            let certificate_path = sub_matches.get_one::<String>("certificate");

            if let Some(path) = certificate_path {
                if sub_matches.get_flag("raw") {
                    let x509_info = match certificate::X509Info::build(path) {
                        Some(x509_info) => x509_info,
                        None => {
                            return Err(Error::new(
                                ErrorKind::InvalidInput,
                                "Cannot read certificate",
                            ))
                        }
                    };

                    print::print_raw_certificate(&x509_info);
                } else {
                    let cert_buf = match fs::read(path) {
                        Ok(cert_buf) => cert_buf,
                        Err(e) => return Err(Error::new(e.kind(), "Cannot read certificate")),
                    };

                    let pem = match parse_x509_pem(&cert_buf) {
                        Ok((_, pem)) => pem,
                        Err(_) => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Cannot read certificate encoded as PEM",
                            ))
                        }
                    };

                    let x509 = match parse_x509_certificate(&pem.contents) {
                        Ok((_, x509)) => x509,
                        Err(_) => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Cannot parse X.509 certificate",
                            ))
                        }
                    };

                    print::print_pretty_certificate(&x509);
                }
            }

            let private_key_path = sub_matches.get_one::<String>("private_key");

            if let Some(path) = private_key_path {
                let priv_key_info = match private_key::PrivKeyInfo::build(path) {
                    Some(priv_key_info) => priv_key_info,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse PKCS#8 private key",
                        ))
                    }
                };

                if sub_matches.get_flag("raw") {
                    print::print_raw_private_key(&priv_key_info);
                } else {
                    print::print_pretty_private_key(&priv_key_info);
                }
            }

            Ok(())
        }
        Some(("render", sub_matches)) => {
            let certificate_path = sub_matches.get_one::<String>("certificate");

            if let Some(path) = certificate_path {
                let x509_info = match certificate::X509Info::build(path) {
                    Some(x509_info) => x509_info,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "Cannot parse X.509 certificate",
                        ))
                    }
                };

                let cert_name_os = match Path::new(path).file_name() {
                    Some(cert_name_os) => cert_name_os,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse certificate filename from path",
                        ))
                    }
                };

                let cert_name = match cert_name_os.to_str() {
                    Some(cert_name) => cert_name,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse certificate filename from path",
                        ))
                    }
                };

                let dot_idx = match cert_name.chars().position(|c| c == '.') {
                    Some(dot_idx) => dot_idx,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse certificate filename from path",
                        ))
                    }
                };

                let cert_name = &cert_name[..dot_idx].replace("-", "_");

                match render::render_certificate(cert_name, &x509_info) {
                    Ok(()) => {}
                    Err(_) => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse X.509 certificate",
                        ))
                    }
                }
            }

            let private_key_path = sub_matches.get_one::<String>("private_key");

            if let Some(path) = private_key_path {
                let priv_key_info = match private_key::PrivKeyInfo::build(path) {
                    Some(priv_key_info) => priv_key_info,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse PKCS#8 private key",
                        ))
                    }
                };

                let key_name_os = match Path::new(path).file_name() {
                    Some(key_name_os) => key_name_os,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse private key file name from path",
                        ))
                    }
                };

                let key_name = match key_name_os.to_str() {
                    Some(key_name) => key_name,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse private key file name from path",
                        ))
                    }
                };

                let dot_idx = match key_name.chars().position(|c| c == '.') {
                    Some(dot_idx) => dot_idx,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse private key file name from path",
                        ))
                    }
                };

                let key_name = &key_name[..dot_idx].replace("-", "_");

                match render::render_private_key(key_name, &priv_key_info) {
                    Ok(()) => {}
                    Err(_) => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot parse PKCS#8 private key",
                        ))
                    }
                }
            }

            Ok(())
        }
        _ => Err(Error::new(ErrorKind::InvalidInput, "Invalid input")),
    }
}
