use anyhow::{anyhow, bail, Context};
use bitcoin_hashes::Hash;
use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    ecdsa,
    key::PrivateKey,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use std::str::FromStr;

use crate::types::{Network as ParamNetwork, TxParams};

pub struct SignedTxResult {
    pub tx_hex: String,
    pub txid: String,
    pub size: usize,
    pub vsize: usize,
}

enum ScriptType {
    P2wpkh,
    P2pkh,
}

fn to_bitcoin_network(n: &ParamNetwork) -> Network {
    match n {
        ParamNetwork::Mainnet => Network::Bitcoin,
        ParamNetwork::Testnet => Network::Testnet,
        ParamNetwork::Signet => Network::Signet,
        ParamNetwork::Regtest => Network::Regtest,
    }
}

pub fn build_and_sign(params: TxParams) -> anyhow::Result<SignedTxResult> {
    let network = to_bitcoin_network(&params.network);
    let secp = Secp256k1::signing_only();

    let private_key =
        PrivateKey::from_wif(&params.private_key_wif).context("秘密鍵（WIF）のパースに失敗")?;
    let public_key = private_key.public_key(&secp);

    if params.utxos.is_empty() {
        bail!("UTXOが指定されていません");
    }
    if params.recipients.is_empty() {
        bail!("送金先が指定されていません");
    }

    // 残高チェック
    let total_input: u64 = params.utxos.iter().map(|u| u.amount_sat).sum();
    let total_output: u64 = params.recipients.iter().map(|r| r.amount_sat).sum();
    let change_amount = total_input.checked_sub(total_output + params.fee_sat).ok_or_else(|| {
        anyhow!(
            "残高不足: 入力={} sat, 出力={} sat, 手数料={} sat",
            total_input,
            total_output,
            params.fee_sat
        )
    })?;

    // インプット構築
    let mut inputs = Vec::new();
    for utxo in &params.utxos {
        let txid = Txid::from_str(&utxo.txid)
            .with_context(|| format!("無効なtxid: {}", utxo.txid))?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(txid, utxo.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
    }

    // アウトプット構築
    let mut outputs = Vec::new();
    for recipient in &params.recipients {
        let addr = Address::from_str(&recipient.address)
            .with_context(|| format!("無効なアドレス: {}", recipient.address))?
            .require_network(network)
            .with_context(|| {
                format!(
                    "アドレス {} はネットワーク {:?} と一致しません",
                    recipient.address, params.network
                )
            })?;
        outputs.push(TxOut {
            value: Amount::from_sat(recipient.amount_sat),
            script_pubkey: addr.script_pubkey(),
        });
    }

    // お釣りアウトプット
    if change_amount > 0 {
        let change_addr_str = params.change_address.as_deref().ok_or_else(|| {
            anyhow!(
                "お釣り {} sat が発生しますが change_address が指定されていません",
                change_amount
            )
        })?;
        let change_addr = Address::from_str(change_addr_str)
            .context("無効なお釣りアドレス")?
            .require_network(network)
            .context("お釣りアドレスのネットワーク不一致")?;
        outputs.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: change_addr.script_pubkey(),
        });
    }

    // 未署名トランザクション
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // ── Phase 1: SighashをすべてまとめてTxを借用したまま計算 ──
    let sighash_data: Vec<([u8; 32], ScriptType)> = {
        let mut cache = SighashCache::new(&tx);
        let mut result = Vec::new();

        for (idx, utxo) in params.utxos.iter().enumerate() {
            let script_pubkey = ScriptBuf::from_hex(&utxo.script_pubkey)
                .with_context(|| {
                    format!("script_pubkey のパースに失敗: UTXO {}:{}", utxo.txid, utxo.vout)
                })?;

            if script_pubkey.is_p2wpkh() {
                let sighash = cache
                    .p2wpkh_signature_hash(
                        idx,
                        &script_pubkey,
                        Amount::from_sat(utxo.amount_sat),
                        EcdsaSighashType::All,
                    )
                    .with_context(|| format!("P2WPKH sighash 計算失敗（入力{}）", idx))?;
                result.push((sighash.to_byte_array(), ScriptType::P2wpkh));
            } else if script_pubkey.is_p2pkh() {
                let sighash = cache
                    .legacy_signature_hash(idx, &script_pubkey, EcdsaSighashType::All as u32)
                    .with_context(|| format!("P2PKH sighash 計算失敗（入力{}）", idx))?;
                result.push((sighash.to_byte_array(), ScriptType::P2pkh));
            } else {
                bail!(
                    "未対応のscriptタイプ（P2WPKHかP2PKHが必要）: UTXO {}:{}",
                    utxo.txid,
                    utxo.vout
                );
            }
        }
        result
    }; // cache（&tx の借用）がここでdrop → tx を変更可能に

    // ── Phase 2: 署名を適用 ──
    for (idx, (hash_bytes, script_type)) in sighash_data.into_iter().enumerate() {
        let msg = Message::from_digest(hash_bytes);
        let raw_sig = secp.sign_ecdsa(&msg, &private_key.inner);
        let ecdsa_sig = ecdsa::Signature {
            signature: raw_sig,
            sighash_type: EcdsaSighashType::All,
        };

        match script_type {
            ScriptType::P2wpkh => {
                // witness = [<sig>, <pubkey>]
                let sig_bytes = ecdsa_sig.serialize();
                let pk_bytes = public_key.inner.serialize();
                let mut witness = Witness::new();
                witness.push(&sig_bytes[..]);
                witness.push(&pk_bytes[..]);
                tx.input[idx].witness = witness;
            }
            ScriptType::P2pkh => {
                // scriptSig = OP_PUSH(<sig>) OP_PUSH(<pubkey>)
                let sig_bytes = ecdsa_sig.serialize();
                let pk_bytes = public_key.inner.serialize();

                let mut script_sig_bytes: Vec<u8> =
                    Vec::with_capacity(1 + sig_bytes.len() + 1 + pk_bytes.len());
                script_sig_bytes.push(sig_bytes.len() as u8);
                script_sig_bytes.extend_from_slice(sig_bytes.as_ref());
                script_sig_bytes.push(pk_bytes.len() as u8);
                script_sig_bytes.extend_from_slice(&pk_bytes);

                tx.input[idx].script_sig = ScriptBuf::from(script_sig_bytes);
            }
        }
    }

    // シリアライズ
    let tx_bytes = serialize(&tx);
    let tx_hex = hex::encode(&tx_bytes);
    let txid = tx.compute_txid().to_string();
    let size = tx_bytes.len();
    let vsize = tx.weight().to_vbytes_ceil() as usize;

    Ok(SignedTxResult { tx_hex, txid, size, vsize })
}
