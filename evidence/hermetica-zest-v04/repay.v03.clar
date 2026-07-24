(define-public (repay (ft <ft-trait>) (amount uint) (on-behalf-of (optional principal)))
  (let ((address (contract-of ft))
        (asset (try! (get-asset address)))
        (asset-id (get id asset))
        ;; defaults to payer (contract-caller) if not specified
        (account (match on-behalf-of behalf behalf contract-caller))
        
        ;; Step 1: Get position WITHOUT resolving prices
        (position (try! (get-position account)))
        (mask (get mask position))
        
        ;; Step 2: Accrue user's positions (populates cache for ztokens)
        (u-debt (accrue-user-debts (get debt position)))
        
        (borrow-index (get index (unwrap-panic (get-cached-indexes asset-id))))
        
        ;; Step 3: Get account debt FIRST to enable safe amount capping
        (account-scaled-debt (get-account-scaled-debt account asset-id))
        
        ;; Step 4: Calculate max repayable amount (actual debt in token), mul-div-up for safe upper bound
        (max-repay-tokens (mul-div-up account-scaled-debt borrow-index INDEX-PRECISION))
        
        ;; Step 5: Cap input amount at actual debt - prevents overflow in scaled calculation
        (safe-amount (min amount max-repay-tokens))
        
        ;; Step 6: Convert to scaled debt (amount is bounded)
        (scaled-debt-repayment (mul-div-down safe-amount INDEX-PRECISION borrow-index))

        (repaid-scaled-debt (min account-scaled-debt scaled-debt-repayment))
        (amount-to-repay (mul-div-up repaid-scaled-debt borrow-index INDEX-PRECISION))
        
        ;; Check if repaying ALL debt for this asset
        (repaying-all (is-eq repaid-scaled-debt account-scaled-debt)))

    ;; preconditions
    (asserts! (is-eq contract-caller tx-sender) ERR-AUTHORIZATION)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (> repaid-scaled-debt u0) ERR-INSUFFICIENT-SCALED-DEBT)

    (try! (vault-system-repay asset-id amount-to-repay ft address))
    ;; update
    (try! (contract-call? .v0-market-vault
                            debt-remove-scaled
                            account
                            repaid-scaled-debt
                            asset-id))
    
    (print {
      action: "repay",
      caller: contract-caller,
      data: {
        payer: contract-caller,
        account: account,
        asset-id: asset-id,
        asset-addr: address,
        amount-requested: amount,
        amount-repaid: amount-to-repay,
        scaled-debt-removed: repaid-scaled-debt,
        borrow-index: borrow-index
      }
    })
    
    (ok amount-to-repay)))