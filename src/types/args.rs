use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub action: ArgCommand,

    /// Path to config file ~/.bw-agent.yaml is used by default
    #[clap(long, short)]
    pub config: Option<String>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ArgCommand {
    /// Spawn bw-agent server
    Run {
        #[clap(short = 'D')]
        foreground: bool,
    },
    /// Encrypt sensitive fields in the specified config file
    Encrypt,
}
