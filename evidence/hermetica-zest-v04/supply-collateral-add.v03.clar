(define-public (supply-collateral-add (ft <ft-trait>) (amount uint) (min-shares uint) (price-feeds (optional (list 3 (buff 8192)))))
  (let ((ft-address (contract-of ft))
        (asset (try! (get-asset ft-address)))
        (asset-id (get id asset))
        (account contract-caller))
    
    ;; Preconditions
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    
    ;; Step 1: Transfer underlying tokens from user to this contract (market)
    (try! (contract-call? ft transfer amount account current-contract none))
    
    ;; Step 2: Deposit to vault to get zTokens (minted to user)
    ;; Now the market has the underlying tokens and can call vault-deposit
    (let ((shares-minted 
            (try! (if (is-eq ft-address ZEST-STX-WRAPPER-CONTRACT)
              ;; For wSTX: use as-contract with-stx pattern
              (as-contract? ((with-stx amount))
                (try! (vault-deposit asset-id amount min-shares account)))
              ;; For other tokens: use as-contract with-ft pattern
              (as-contract? ((with-ft ft-address "*" amount))
                (try! (vault-deposit asset-id amount min-shares account)))))))
      
      ;; Step 3: Add the minted zTokens as collateral
      (if (is-eq asset-id STX) (collateral-add .v0-vault-stx shares-minted price-feeds)
      (if (is-eq asset-id sBTC) (collateral-add .v0-vault-sbtc shares-minted price-feeds)
      (if (is-eq asset-id stSTX) (collateral-add .v0-vault-ststx shares-minted price-feeds)
      (if (is-eq asset-id USDC) (collateral-add .v0-vault-usdc shares-minted price-feeds)
      (if (is-eq asset-id USDH) (collateral-add .v0-vault-usdh shares-minted price-feeds)
      (if (is-eq asset-id stSTXbtc) (collateral-add .v0-vault-ststxbtc shares-minted price-feeds)
      ERR-UNKNOWN-VAULT))))))))
)