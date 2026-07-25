
(impl-trait .vault-traits.flash-callback)

(use-trait flash-callback .vault-traits.flash-callback)

(define-constant OFFSET-OP u0)
(define-constant OFFSET-VERSION u3)
(define-constant OFFSET-BORROWER u4)
(define-constant OFFSET-DEBT-AMOUNT u25)
(define-constant OFFSET-MIN-COLLATERAL u41)
(define-constant OFFSET-MIN-UNDERLYING u57)
(define-constant OFFSET-MIN-PROFIT u73)
(define-constant OFFSET-VAULT-ID u89)
(define-constant OFFSET-COLLATERAL-ID u90)
(define-constant OFFSET-DEBT-ID u91)
(define-constant OFFSET-MINT-SLIPPAGE-BPS u92)
(define-constant OFFSET-PNAU-LEN u126)
(define-constant OFFSET-PNAU-START u128)

(define-constant OP-FLASH-MINT-USDH u7)

(define-constant AID-ZSBTC u3)
(define-constant AID-SBTC u2)
(define-constant AID-USDH u8)

(define-constant VID-SBTC u2)

(define-constant MAX-MINT-SLIPPAGE-BPS u500)

(define-constant VERSION-MAINNET-SINGLESIG u22)
(define-constant VERSION-MAINNET-MULTISIG u20)

(define-constant ERR-NO-DATA (err u930001))
(define-constant ERR-UNKNOWN-OP (err u930002))
(define-constant ERR-UNKNOWN-VAULT (err u930003))
(define-constant ERR-UNKNOWN-PAIR (err u930004))
(define-constant ERR-UNAUTHORIZED (err u930005))
(define-constant ERR-INSUFFICIENT-PROFIT (err u930006))
(define-constant ERR-NO-PRICE-FEED (err u930007))
(define-constant ERR-NO-MIN-PROFIT (err u930008))
(define-constant ERR-NO-MINT-SLIPPAGE (err u930009))
(define-constant ERR-SLIPPAGE-TOO-HIGH (err u930010))
(define-constant ERR-UNKNOWN-VERSION-BYTE (err u930011))

(define-data-var contract-owner principal tx-sender)
(define-map authorized-operators principal bool)

(define-data-var callback-caller (optional principal) none)
(define-data-var callback-active bool false)
(define-data-var callback-pre-balance uint u0)

(define-private (get-u8 (data (buff 4096)) (pos uint))
  (match (element-at? data pos)
    byte (buff-to-uint-be byte)
    u0))

(define-private (decode-u16 (data (buff 4096)) (start uint))
  (let ((segment (default-to 0x (slice? data start (+ start u2)))))
    (buff-to-uint-be (unwrap-panic (as-max-len? segment u2)))))

(define-private (decode-u128 (data (buff 4096)) (start uint))
  (let ((segment (default-to 0x (slice? data start (+ start u16)))))
    (buff-to-uint-be (unwrap-panic (as-max-len? segment u16)))))

(define-private (decode-principal (data (buff 4096)) (start uint))
  (let (
    (version-byte (get-u8 data start))
    (hash-segment (default-to 0x (slice? data (+ start u1) (+ start u21))))
    (hash-20 (unwrap-panic (as-max-len? hash-segment u20)))
  )
    (principal-construct-from-version-and-hash version-byte hash-20)))

(define-private (principal-construct-from-version-and-hash (version uint) (hash (buff 20)))
  (if (is-eq version VERSION-MAINNET-SINGLESIG)
      (unwrap-panic (principal-construct? 0x16 hash))
      (unwrap-panic (principal-construct? 0x14 hash))))

(define-private (extract-price-feed (data (buff 4096)))
  (let ((pnau-len (decode-u16 data OFFSET-PNAU-LEN)))
    (match (slice? data OFFSET-PNAU-START (+ OFFSET-PNAU-START pnau-len))
      sliced (as-max-len? sliced u8192)
      none)))

(define-private (extract-price-feed-list (data (buff 4096)))
  (match (extract-price-feed data)
    feed (as-max-len? (list feed) u3)
    none))

(define-read-only (get-owner)
  (var-get contract-owner))

(define-read-only (is-authorized-operator (op principal))
  (default-to false (map-get? authorized-operators op)))

(define-public (set-operator (op principal) (authorized bool))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-UNAUTHORIZED)
    (ok (map-set authorized-operators op authorized))))

(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-UNAUTHORIZED)
    (ok (var-set contract-owner new-owner))))

(define-private (assert-authorized-operator)
  (ok (asserts! (is-authorized-operator tx-sender) ERR-UNAUTHORIZED)))

(define-public (execute
    (self <flash-callback>)
    (data (buff 4096))
    (flashloan-amount uint))
  (begin
    (asserts! (is-eq (contract-of self) current-contract) ERR-UNAUTHORIZED)
    (try! (assert-authorized-operator))
    (let (
      (op (get-u8 data OFFSET-OP))
      (vault-id (get-u8 data OFFSET-VAULT-ID))
      (borrower-version (get-u8 data OFFSET-BORROWER))
      (pnau-len (decode-u16 data OFFSET-PNAU-LEN))
      (slippage-raw (decode-u16 data OFFSET-MINT-SLIPPAGE-BPS))
      (min-profit (decode-u128 data OFFSET-MIN-PROFIT))
    )
      (asserts! (is-eq op OP-FLASH-MINT-USDH) ERR-UNKNOWN-OP)
      (asserts! (is-eq vault-id VID-SBTC) ERR-UNKNOWN-VAULT)
      (asserts!
        (or
          (is-eq borrower-version VERSION-MAINNET-SINGLESIG)
          (is-eq borrower-version VERSION-MAINNET-MULTISIG))
        ERR-UNKNOWN-VERSION-BYTE)
      (asserts! (> pnau-len u0) ERR-NO-PRICE-FEED)
      (asserts! (> slippage-raw u0) ERR-NO-MINT-SLIPPAGE)
      (asserts! (<= slippage-raw MAX-MINT-SLIPPAGE-BPS) ERR-SLIPPAGE-TOO-HIGH)
      (asserts! (> min-profit u0) ERR-NO-MIN-PROFIT)
      (var-set callback-caller (some tx-sender))
      (var-set callback-active true)
      (as-contract? ((with-all-assets-unsafe))
        (begin
          (var-set callback-pre-balance
            (unwrap-panic
              (contract-call?
                'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance tx-sender)))
          (try! (contract-call?
            .v0-vault-sbtc
            flashloan
            flashloan-amount
            (some current-contract)
            self
            (some data))))))))

(define-public (callback
    (amount uint)
    (fee uint)
    (data (optional (buff 4096))))
  (let (
    (buf (unwrap! data ERR-NO-DATA))
    (op (get-u8 buf OFFSET-OP))
    (caller (unwrap! (var-get callback-caller) ERR-UNAUTHORIZED))
  )
    (asserts!
      (is-eq contract-caller .v0-vault-sbtc)
      ERR-UNAUTHORIZED)
    (asserts! (var-get callback-active) ERR-UNAUTHORIZED)
    (var-set callback-active false)
    (var-set callback-caller none)
    (asserts! (is-eq op OP-FLASH-MINT-USDH) ERR-UNKNOWN-OP)
    (handle-flash-mint-usdh amount fee buf caller)))

(define-private (handle-flash-mint-usdh
    (amount uint) (fee uint) (buf (buff 4096)) (caller principal))
  (let (
    (coll-id (get-u8 buf OFFSET-COLLATERAL-ID))
    (debt-id (get-u8 buf OFFSET-DEBT-ID))
    (borrower (decode-principal buf OFFSET-BORROWER))
    (debt-amount (decode-u128 buf OFFSET-DEBT-AMOUNT))
    (min-coll (decode-u128 buf OFFSET-MIN-COLLATERAL))
    (min-und (decode-u128 buf OFFSET-MIN-UNDERLYING))
    (min-profit (decode-u128 buf OFFSET-MIN-PROFIT))
    (mint-slippage (decode-u16 buf OFFSET-MINT-SLIPPAGE-BPS))
    (price-feed (extract-price-feed buf))
    (price-feed-list (extract-price-feed-list buf))
    (pre-balance (var-get callback-pre-balance))
  )
    (asserts! (is-eq debt-id AID-USDH) ERR-UNKNOWN-PAIR)
    (asserts! (or (is-eq coll-id AID-SBTC) (is-eq coll-id AID-ZSBTC)) ERR-UNKNOWN-PAIR)

    (as-contract? ((with-all-assets-unsafe))
      (begin
        (try! (contract-call?
          'SPN5AKG35QZSK2M8GAMR4AFX45659RJHDW353HSG.minting-auto-v1-2 mint
          'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
          debt-amount
          mint-slippage
          none
          price-feed
          {
            pyth-storage-contract:  'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-storage-v4,
            pyth-decoder-contract:  'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.pyth-pnau-decoder-v3,
            wormhole-core-contract: 'SP1CGXWEAMG6P6FT04W66NVGJ7PQWMDAC19R7PJ0Y.wormhole-core-v4
          }))

        (if (is-eq coll-id AID-ZSBTC)
          (begin
            (try! (contract-call?
              .v0-4-market liquidate-redeem
              borrower
              .v0-vault-sbtc
              'SPN5AKG35QZSK2M8GAMR4AFX45659RJHDW353HSG.usdh-token-v1
              debt-amount min-coll min-und none price-feed-list))
            true)
          (begin
            (try! (contract-call?
              .v0-4-market liquidate
              borrower
              'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
              'SPN5AKG35QZSK2M8GAMR4AFX45659RJHDW353HSG.usdh-token-v1
              debt-amount min-coll none price-feed-list))
            true))

        (let (
          (sbtc-post
            (unwrap-panic
              (contract-call?
                'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance tx-sender)))
          (total-repayment (+ amount fee))
        )
          (asserts!
            (>= sbtc-post (+ pre-balance total-repayment min-profit))
            ERR-INSUFFICIENT-PROFIT)
          (let ((profit (- sbtc-post (+ pre-balance total-repayment))))
            (if (> profit u0)
              (try!
                (contract-call?
                  'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                  transfer profit tx-sender caller none))
              true)
            (var-set callback-pre-balance u0)
            (print {
              action: "flash-mint-usdh",
              borrower: borrower,
              debt-amount: debt-amount,
              pre-balance: pre-balance,
              total-repayment: total-repayment,
              profit: profit,
              profit-recipient: caller
            })
            true))))))
