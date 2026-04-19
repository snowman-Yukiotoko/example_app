use bitcoin::{
    key::{CompressedPublicKey, PrivateKey},
    secp256k1::Secp256k1,
    Address, Network,
};
use rand::rngs::OsRng;

pub fn run(network_str: &str) -> anyhow::Result<()> {
    let network = match network_str {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => anyhow::bail!("不明なネットワーク: {}  (mainnet/testnet/signet/regtest)", other),
    };

    let secp = Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::new(&mut OsRng);
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    let private_key = PrivateKey::new(secret_key, network);
    let compressed_pubkey = CompressedPublicKey(public_key);

    // P2WPKH アドレス (bech32)
    let p2wpkh_addr = Address::p2wpkh(&compressed_pubkey, network);
    let script_pubkey = p2wpkh_addr.script_pubkey();

    println!("=== キーペア生成結果 ===");
    println!("ネットワーク     : {:?}", network);
    println!();
    println!("秘密鍵 (WIF)     : {}", private_key.to_wif());
    println!("公開鍵 (hex)     : {}", compressed_pubkey);
    println!();
    println!("アドレス (P2WPKH): {}", p2wpkh_addr);
    println!("scriptPubKey     : {}", hex::encode(script_pubkey.as_bytes()));
    println!();
    println!("=== テストネット利用手順 ===");
    println!("1. 上記アドレスに faucet から tBTC を送金:");
    println!("   https://coinfaucet.eu/en/btc-testnet/");
    println!("   https://testnet-faucet.mempool.co/");
    println!();
    println!("2. Testnet Explorer で UTXO を確認:");
    println!("   https://mempool.space/testnet/address/{}", p2wpkh_addr);
    println!();
    println!("3. JSON 入力ファイルを作成し btc-tx で署名:");
    println!("   btc-tx sign --input tx.json");
    println!();
    println!("4. 署名済み tx を broadcast:");
    println!("   https://mempool.space/testnet/tx/push");
    println!();
    println!("[警告] 秘密鍵は安全な場所に保管してください");

    Ok(())
}
