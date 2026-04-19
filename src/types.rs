use serde::Deserialize;

/// 対象ネットワーク
#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

/// 使用するUTXO
#[derive(Deserialize, Debug)]
pub struct Utxo {
    /// トランザクションID（hex）
    pub txid: String,
    /// アウトプットインデックス
    pub vout: u32,
    /// 金額（satoshi）
    pub amount_sat: u64,
    /// UTXOのscriptPubKey（hex）
    pub script_pubkey: String,
}

/// 送金先
#[derive(Deserialize, Debug)]
pub struct Recipient {
    /// Bitcoinアドレス
    pub address: String,
    /// 金額（satoshi）
    pub amount_sat: u64,
}

/// トランザクション構築パラメータ
#[derive(Deserialize, Debug)]
pub struct TxParams {
    /// ネットワーク
    pub network: Network,
    /// 秘密鍵（WIF形式）
    pub private_key_wif: String,
    /// 使用するUTXOリスト
    pub utxos: Vec<Utxo>,
    /// 送金先リスト
    pub recipients: Vec<Recipient>,
    /// お釣りアドレス（省略時はお釣りなし）
    pub change_address: Option<String>,
    /// 手数料（satoshi）
    pub fee_sat: u64,
}
