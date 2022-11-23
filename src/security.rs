use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Strike Wallet",
    project_url: "https://strikeprotocols.com",
    contacts: "email:security@strikeprotocols.com",
    policy: "https://github.com/StrikeProtocols/strike-solana-wallet/blob/master/SECURITY.md",
    source_code: "https://github.com/StrikeProtocols/strike-solana-wallet"
}
