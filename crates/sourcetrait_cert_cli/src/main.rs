mod run;

fn main() {
    if let Err(e) = run::run() {
        eprintln!("srcert: {e}");
        std::process::exit(1);
    }
}
