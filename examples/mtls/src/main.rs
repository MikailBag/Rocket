#![feature(plugin, decl_macro)]
#![plugin(rocket_codegen)]

extern crate rocket;

use rocket::http::tls::MutualTlsUser;

#[cfg(test)] mod tests;

#[get("/")]
fn hello(_mtls: MutualTlsUser) -> String {
    format!("Hello, world!")
    // format!("{}", mtls.get_common_names()[0])
}

fn main() {
    rocket::ignite().mount("/", routes![hello]).launch();
}
