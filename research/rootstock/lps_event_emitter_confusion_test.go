package pegout_test

import (
    "context"
    "encoding/hex"
    "math/big"
    "strings"
    "testing"

    "github.com/rsksmart/liquidity-provider-server/internal/adapters/dataproviders/rootstock"
    "github.com/rsksmart/liquidity-provider-server/internal/entities"
    "github.com/rsksmart/liquidity-provider-server/internal/entities/blockchain"
    "github.com/rsksmart/liquidity-provider-server/internal/entities/quote"
    "github.com/rsksmart/liquidity-provider-server/internal/usecases"
    "github.com/rsksmart/liquidity-provider-server/internal/usecases/pegout"
    "github.com/rsksmart/liquidity-provider-server/test"
    "github.com/rsksmart/liquidity-provider-server/test/mocks"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
)

const forgedEmitter = "0x000000000000000000000000000000000000dEaD"

// This test reproduces an event-emitter confusion in the exact v2.5.1 LPS path:
// ParseDepositEvent selects the first log with the PegOutDeposit topic without
// considering the emitter address. SendPegoutUseCase only checks the emitter
// after parsing that first match, and treats a mismatch as terminal. A helper
// contract can therefore emit the same event before making a valid LBC deposit
// in the same transaction receipt. The valid LBC event is present but ignored.
func TestAuditForgedPrecedingDepositEventCausesTerminalPegoutFailure(t *testing.T) {
    retained := sendPegoutRetainedQuote
    retained.UserRskTxHash = "0x5b5c5d"

    receipt := &blockchain.TransactionReceipt{
        TransactionHash:   retained.UserRskTxHash,
        BlockHash:         blockHash,
        BlockNumber:       blockNumber,
        From:              "0x000000000000000000000000000000000000bEEF",
        To:                sendPegoutTestQuote.LbcAddress,
        CumulativeGasUsed: big.NewInt(500),
        GasUsed:           big.NewInt(500),
        Value:             entities.NewWei(8500),
    }
    receipt = test.AddDepositLogFromQuote(t, receipt, sendPegoutTestQuote, retained)

    legitimate := receipt.Logs[0]
    legitimate.Index = 1
    forged := legitimate
    forged.Address = forgedEmitter
    forged.Index = 0
    receipt.Logs = []blockchain.TransactionLog{forged, legitimate}

    parsed, err := rootstock.ParseDepositEvent(*receipt)
    require.NoError(t, err)
    require.Equal(t, forgedEmitter, parsed.RawLog.Address,
        "production parser must be shown selecting the attacker event")
    require.Equal(t, sendPegoutTestQuote.LbcAddress, receipt.Logs[1].Address,
        "a valid LBC event must still exist later in the same receipt")

    btcWallet := new(mocks.BitcoinWalletMock)
    rsk := new(mocks.RootstockRpcServerMock)
    eventBus := new(mocks.EventBusMock)
    mutex := new(mocks.MutexMock)
    quoteRepository := new(mocks.PegoutQuoteRepositoryMock)
    pegoutContract := new(mocks.PegoutContractMock)

    rsk.On("GetHeight", test.AnyCtx).Return(uint64(450), nil).Once()
    rsk.On("GetTransactionReceipt", test.AnyCtx, retained.UserRskTxHash).Return(*receipt, nil).Once()
    quoteRepository.On("GetQuote", test.AnyCtx, retained.QuoteHash).Return(&sendPegoutTestQuote, nil).Once()

    expectedRetained := retained
    expectedRetained.State = quote.PegoutStateSendPegoutFailed
    quoteRepository.On("UpdateRetainedQuote", test.AnyCtx, expectedRetained).Return(nil).Once()

    pegoutContract.EXPECT().PausedStatus().Return(blockchain.PauseStatus{IsPaused: false}, nil).Once()
    eventBus.On("Publish", mock.MatchedBy(func(event quote.PegoutBtcSentToUserEvent) bool {
        return assert.Equal(t, expectedRetained, event.RetainedQuote) &&
            assert.Equal(t, sendPegoutTestQuote, event.PegoutQuote) &&
            assert.ErrorContains(t, event.Error, "invalid LBC address") &&
            assert.ErrorIs(t, event.Error, usecases.NonRecoverableError)
    })).Return().Once()

    useCase := pegout.NewSendPegoutUseCase(
        btcWallet,
        quoteRepository,
        blockchain.Rpc{Rsk: rsk},
        eventBus,
        blockchain.RskContracts{PegOut: pegoutContract},
        mutex,
        rootstock.ParseDepositEvent,
    )

    err = useCase.Run(context.Background(), retained)
    require.Error(t, err)
    require.ErrorContains(t, err, "invalid LBC address")
    require.ErrorIs(t, err, usecases.NonRecoverableError)

    quoteRepository.AssertExpectations(t)
    rsk.AssertExpectations(t)
    eventBus.AssertExpectations(t)
    pegoutContract.AssertExpectations(t)
    btcWallet.AssertNotCalled(t, "SendWithOpReturn", mock.Anything, mock.Anything, mock.Anything)
    mutex.AssertNotCalled(t, "Lock")
    mutex.AssertNotCalled(t, "Unlock")
    pegoutContract.AssertNotCalled(t, "IsPegOutQuoteCompleted", mock.Anything)
}

// Fixed-control parser: filter by the expected LBC emitter before applying the
// current ABI event decoder. The exact forged receipt then resolves to the real
// LBC event rather than the attacker-controlled first match.
func TestAuditEmitterBoundParserSelectsLegitimateEvent(t *testing.T) {
    retained := sendPegoutRetainedQuote
    receipt := &blockchain.TransactionReceipt{
        TransactionHash: retained.UserRskTxHash,
        BlockHash:       blockHash,
        BlockNumber:     blockNumber,
        From:            "0x000000000000000000000000000000000000bEEF",
        To:              sendPegoutTestQuote.LbcAddress,
    }
    receipt = test.AddDepositLogFromQuote(t, receipt, sendPegoutTestQuote, retained)
    legitimate := receipt.Logs[0]
    forged := legitimate
    forged.Address = forgedEmitter
    receipt.Logs = []blockchain.TransactionLog{forged, legitimate}

    emitterBound := *receipt
    emitterBound.Logs = nil
    for _, eventLog := range receipt.Logs {
        if strings.EqualFold(eventLog.Address, sendPegoutTestQuote.LbcAddress) {
            emitterBound.Logs = append(emitterBound.Logs, eventLog)
        }
    }

    parsed, err := rootstock.ParseDepositEvent(emitterBound)
    require.NoError(t, err)
    assert.True(t, strings.EqualFold(sendPegoutTestQuote.LbcAddress, parsed.RawLog.Address))

    expectedQuoteHashBytes, err := hex.DecodeString(retained.QuoteHash)
    require.NoError(t, err)
    assert.Equal(t, expectedQuoteHashBytes, parsed.RawLog.Topics[1][:])
}
