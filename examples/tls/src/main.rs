#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;

use rocket::http::tls::ClientTls;
use std::borrow::Cow;

#[get("/")]
fn hello(auth: Option<ClientTls>) -> Cow<'static, str> {
    match auth {
        None => "Hello, anonymous user".into(),
        Some(info) => {
            let tbs = match info.end_entity.parse() {
                Ok(t) => t.tbs_certificate,
                Err(err) => return format!("I did not understand your certificate: {}", err).into()
            };
            let san = tbs
                .subject_alternative_name()
                .map(|(_, sans)| sans.general_names.as_slice())
                .unwrap_or(&[]);
            format!("Hello, {:?}", san).into()
        }
    }
}

#[get("/secret")]
fn secret(_authenticated: ClientTls) -> &'static str {
    "secret stuff"
}

#[launch]
fn rocket() -> rocket::Rocket {
    // See `Rocket.toml` and `Cargo.toml` for TLS configuration.
    rocket::ignite().mount("/", routes![hello, secret])
}
