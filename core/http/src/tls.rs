pub use self::hyper_sync_rustls::{util, WrappedStream, ServerSession, TlsServer};
pub use self::rustls::{Certificate, PrivateKey, RootCertStore, internal::pemfile};
pub use self::dns_lookup::lookup_addr;

use self::openssl::x509::X509;
use self::time::{Tm, strptime, ParseError};
use self::untrusted::Input;
use self::webpki::{EndEntityCert, DNSNameRef};

type DateTime = Tm;

/// Convert openssl ASN.1 time to a `DateTime`
fn asn1time_to_datetime(dt: &openssl::asn1::Asn1TimeRef) -> Result<DateTime, ParseError> {
    // Sep  1 10:02:28 2017 GMT
    let s = format!("{}", dt);
    // strip GMT and any space-padding
    let s = s.trim_right_matches(" GMT").replace("  ", " ");

    let fmt = "%b %d %H:%M:%S %Y";
    strptime(&s, fmt)
}


/// Find the first `Certificate` valid for the given DNS name
fn first_valid_cert_for_name<'a>(dns_name: DNSNameRef, certs: &'a [Certificate]) -> Option<&'a Certificate> {
    certs.iter()
        .find(|cert| {
            let cert_input = Input::from(cert.as_ref());
            EndEntityCert::from(cert_input)
                .and_then(|ee| ee.verify_is_valid_for_dns_name(dns_name).map(|_| true))
                .unwrap_or(false)
        })
}

/// Given a domain name and a set of `Certificate`s, return the first certificate
/// that matches the domain name
pub fn find_valid_cert_for_peer<'a>(name: &'a str, certs: &'a [Certificate]) -> Result<&'a Certificate, ()> {
    let input = Input::from(name.as_bytes());
    let domain_name = DNSNameRef::try_from_ascii(input)?;

    // Find the first valid cert for the given name
    let valid_cert = first_valid_cert_for_name(domain_name, &certs).ok_or(())?;

    Ok(valid_cert)
}

/// Client MTLS certificate information.
///
/// The `MutualTlsUser` type specifies MTLS being required for the route and retrieves client
/// certificate information.
///
/// #Usage
///
/// A `MutualTlsUser` can be retrieved via its `FromRequest` implementation as a request guard.
/// Information of the certificate with a matching common name as a reverse DNS lookup of the
/// client IP address from the accepted certificate chain can be retrieved via the
/// `get_common_names`, `get_not_before`, and `get_not_after`.
///
/// ##Examples
///
/// The following short snippet shows `MutualTlsUser` being used as a request guard in a handler to
/// verify the client's certificate and print the common names of the client.
///
/// ```rust
/// # #![feature(plugin, decl_macro)]
/// # #![plugin(rocket_codegen)]
/// # extern crate rocket;
/// use rocket::http::tls::MutualTlsUser;
///
/// #[get("/message")]
/// fn message(mtls:MutualTlsUser) {
///     let common_names = mtls.get_common_names();
///     for name in common_names {
///         println!("{}", name);
///     }
/// }
///
/// # fn main() { }
/// ```
///
#[derive(Debug)]
pub struct MutualTlsUser {
    common_names: Vec<String>,
    not_before: DateTime,
    not_after: DateTime,
}

impl MutualTlsUser {
    // TODO: return a Result
    pub fn new(peer_cert: &Certificate) -> Option<MutualTlsUser> {
        // Generate an x509 using the certificate provided
        let x509 = X509::from_der(peer_cert.as_ref()).ok()?;

        // Retrieve alt names and store them into a Vec<String>
        let alt_names = x509.subject_alt_names()?;
        let mut common_names = Vec::new();
        for name in alt_names {
            common_names.push(name.dnsname()?.to_string())
        }

        // Retrieve certificate start time
        let not_before = asn1time_to_datetime(x509.not_before()).ok()?;

        // Retrieve certificate end time
        let not_after = asn1time_to_datetime(x509.not_after()).ok()?;

        Some(MutualTlsUser {
            common_names,
            not_before,
            not_after,
        })
    }

    /// Return the client's common names.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate rocket;
    /// use rocket::http::tls::MutualTlsUser;
    ///
    /// fn handler(mtls: MutualTlsUser) {
    ///     let cert_common_names = mtls.get_common_names();
    /// }
    /// ```
    pub fn get_common_names(&self) -> &[String] {
        &self.common_names
    }

    /// Return the client's certificate's validity period start time.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate rocket;
    /// use rocket::http::tls::MutualTlsUser;
    ///
    /// fn handler(mtls: MutualTlsUser) {
    ///     let cert_start_time = mtls.get_not_before();
    /// }
    /// ```
    pub fn get_not_before(&self) -> &DateTime {
        &self.not_before
    }

    /// Return the client's certificate's validity period end time.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate rocket;
    /// use rocket::http::tls::MutualTlsUser;
    ///
    /// fn handler(mtls: MutualTlsUser) {
    ///     let cert_end_time = mtls.get_not_after();
    /// }
    /// ```
    pub fn get_not_after(&self) -> &DateTime {
        &self.not_after
    }
}
