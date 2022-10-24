use clap_serde_derive::{
   clap::{self, Parser},
   ClapSerde,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
   #[clap(short, long)]
   pub config: String,

   #[clap(flatten)]
   pub user_config: <crate::types::Config as ClapSerde>::Opt
}


// #[derive(ClapSerde, Serialize)]
// #[derive(Debug)]
// #[clap(author, version, about)]
// pub struct Args {
//    /// Input files
//    pub input: Vec<std::path::PathBuf>,

//    /// String argument
//    #[clap(short, long)]
//    name: String,

//    /// Skip serde deserialize
//    #[default(13)]
//    #[serde(skip_deserializing)]
//    #[clap(long = "num")]
//    pub clap_num: u32,

//    /// Skip clap
//    #[serde(rename = "number")]
//    #[clap(skip)]
//    pub serde_num: u32,

//    /// Recursive fields
//    #[clap_serde]
//    #[clap(flatten)]
//    pub suboptions: SubConfig,
// }