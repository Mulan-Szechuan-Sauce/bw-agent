use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
   #[clap(short, long)]
   pub config: String,
}
