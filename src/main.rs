mod system_setup;
mod credential_issuance;
mod app_credential;

fn main() {
    // You can call the system setup demo, then the credential issuance demo.
    system_setup::run();
    credential_issuance::run_credential_issuance();
    app_credential::run_app_credential();
}
