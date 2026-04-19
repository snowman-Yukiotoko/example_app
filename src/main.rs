use clap::{Parser, Subcommand};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

mod keygen;
mod transaction;
mod types;

/// Bitcoin 署名済みトランザクション生成ツール（オフライン動作）
#[derive(Parser)]
#[command(name = "btc-tx", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// 入力JSONファイル（省略時は stdin から読み込み）
    #[arg(short, long, value_name = "FILE", global = false)]
    input: Option<PathBuf>,

    /// 出力ファイル（省略時は stdout に出力）
    #[arg(short, long, value_name = "FILE", global = false)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// 署名済みトランザクションを生成する（デフォルト）
    Sign {
        /// 入力JSONファイル（省略時は stdin から読み込み）
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// 出力ファイル（省略時は stdout に出力）
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// テスト用キーペアとアドレスを生成する
    Keygen {
        /// ネットワーク [mainnet|testnet|signet|regtest]
        #[arg(short, long, default_value = "testnet")]
        network: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Keygen { network }) => keygen::run(&network),
        Some(Command::Sign { input, output }) => run_sign(input, output),
        // サブコマンドなし → sign として扱う
        None => run_sign(cli.input, cli.output),
    }
}

fn run_sign(input: Option<PathBuf>, output: Option<PathBuf>) -> anyhow::Result<()> {
    let json = match &input {
        Some(path) => fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("入力ファイル読み込み失敗: {}", e))?,
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| anyhow::anyhow!("stdin 読み込み失敗: {}", e))?;
            buf
        }
    };

    let params: types::TxParams =
        serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("JSON パース失敗: {}", e))?;

    let result = transaction::build_and_sign(params)?;

    eprintln!("TXID : {}", result.txid);
    eprintln!("Size : {} bytes ({} vbytes)", result.size, result.vsize);
    eprintln!("---");

    let output_content = format!("{}\n", result.tx_hex);

    match &output {
        Some(path) => {
            fs::write(path, &output_content)
                .map_err(|e| anyhow::anyhow!("出力ファイル書き込み失敗: {}", e))?;
            eprintln!("署名済みトランザクションを {} に書き込みました", path.display());
        }
        None => print!("{}", output_content),
    }

    Ok(())
}
