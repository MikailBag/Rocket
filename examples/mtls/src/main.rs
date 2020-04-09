#![feature(plugin, decl_macro)]
#![plugin(rocket_codegen)]

extern crate rocket;

use rocket::http::tls::MutualTlsUser;

#[cfg(test)] mod tests;

#[get("/")]
fn hello(mtls: MutualTlsUser) -> String {
    format!("Hello, MTLS world, {}!", mtls.subject_name())
}

fn main() {
    rocket::ignite().mount("/", routes![hello]).launch();
}
