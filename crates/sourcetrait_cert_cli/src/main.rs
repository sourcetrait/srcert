mod run;
mod style;

fn main() {
    if let Err(failed) = run::run() {
        style::line(style::Kind::Fail, &failed.to_string());
        std::process::exit(1);
    }
}
