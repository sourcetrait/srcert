mod run;
mod style;

fn main() {
    if let Err(failed) = run::run() {
        run::report(&failed);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    mod style;
}
