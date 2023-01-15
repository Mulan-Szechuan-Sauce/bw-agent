use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub action: Command,

    #[clap(long, short)]
    pub config: Option<String>,
}

#[derive(clap::Subcommand)]
pub enum Command {
    Run,
    Encrypt,
}
