package fetcher

import (
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

type mainnetRequest struct {
	peer string
	txs  []common.Hash
	mask types.CustodyBitmap
}

func mainnetWait(t *testing.T, step <-chan struct{}) {
	t.Helper()
	select {
	case <-step:
	case <-time.After(2 * time.Second):
		t.Fatal("BlobFetcher loop did not acknowledge operation")
	}
}

func mainnetDrain(step <-chan struct{}) {
	for {
		select {
		case <-step:
		default:
			return
		}
	}
}

func mainnetPick(fetcher *BlobFetcher, selector byte) (mainnetRequest, bool) {
	peers := make([]string, 0, len(fetcher.requests))
	for peer, reqs := range fetcher.requests {
		if len(reqs) > 0 {
			peers = append(peers, peer)
		}
	}
	if len(peers) == 0 {
		return mainnetRequest{}, false
	}
	sort.Strings(peers)
	peer := peers[int(selector)%len(peers)]
	reqs := fetcher.requests[peer]
	req := reqs[int(selector/5)%len(reqs)]
	return mainnetRequest{peer: peer, txs: slices.Clone(req.txs), mask: req.cells}, true
}

func mainnetCells(mask types.CustodyBitmap, mutate byte) []kzg4844.Cell {
	cells := slices.Clone(selectMultiBlobCells(testBlobSidecars[0], mask))
	switch mutate % 4 {
	case 1:
		if len(cells) > 0 {
			cells = cells[:len(cells)-1]
		}
	case 2:
		cells = append(cells, kzg4844.Cell{})
	case 3:
		if len(cells) > 0 {
			cells[0][0] ^= 0x40
		}
	}
	return cells
}

func mainnetResponse(req mainnetRequest, variant byte) ([]common.Hash, [][]kzg4844.Cell) {
	hashes := slices.Clone(req.txs)
	cells := make([][]kzg4844.Cell, len(hashes))
	for i := range cells {
		cells[i] = mainnetCells(req.mask, variant)
	}
	switch variant % 6 {
	case 1:
		if len(hashes) > 1 {
			hashes, cells = hashes[:len(hashes)-1], cells[:len(cells)-1]
		}
	case 2:
		slices.Reverse(hashes)
		slices.Reverse(cells)
	case 3:
		if len(hashes) > 0 {
			hashes = append(hashes, hashes[0])
			cells = append(cells, slices.Clone(cells[0]))
		}
	case 4:
		hashes = append(hashes, common.Hash{0xdd})
		cells = append(cells, mainnetCells(req.mask, 0))
	case 5:
		if len(cells) > 0 {
			cells[0] = nil
		}
	}
	return hashes, cells
}

func mainnetAssert(t *testing.T, fetcher *BlobFetcher) {
	t.Helper()
	if fetcher.custody != types.CustodyBitmapAll {
		t.Fatal("current-mainnet control left full-custody mode")
	}
	if len(fetcher.partial) != 0 || len(fetcher.waitlist) != 0 || len(fetcher.waittime) != 0 {
		t.Fatal("current-mainnet full-custody path entered partial availability state")
	}
	for peer, reqs := range fetcher.requests {
		if len(reqs) == 0 {
			t.Fatalf("empty request list for peer %q", peer)
		}
		for _, req := range reqs {
			if req == nil || len(req.txs) == 0 || req.cells != types.CustodyBitmapData {
				t.Fatalf("invalid full-custody request for peer %q", peer)
			}
			for _, hash := range req.txs {
				if fetcher.fetches[hash] == nil {
					t.Fatalf("stale request references discarded fetch: %x", hash)
				}
			}
		}
	}
}

func runMainnetMachine(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 || len(data) > 512 {
		return
	}
	peers := []string{"A", "B", "C", "D"}
	fetcher := NewBlobFetcher(
		BlobFetcherFunctions{
			HasPayload:    func(common.Hash) bool { return false },
			AddCells:      func(common.Hash, map[string]*PeerCellDelivery, types.CustodyBitmap) {},
			FetchPayloads: func(string, []common.Hash, types.CustodyBitmap) error { return nil },
			DropPeer:      func(string) {},
		},
		types.CustodyBitmapAll,
		nil,
		15,
	)
	clock := new(mclock.Simulated)
	step := make(chan struct{}, 64)
	fetcher.clock, fetcher.step = clock, step
	done := make(chan struct{})
	go func() {
		defer close(done)
		fetcher.loop()
	}()
	defer func() {
		mainnetDrain(step)
		close(fetcher.quit)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("BlobFetcher loop did not terminate")
		}
	}()

	count := 8 + len(data)%48
	for i := 0; i < count; i++ {
		a := data[(1+i*4)%len(data)]
		b := data[(2+i*4)%len(data)]
		c := data[(3+i*4)%len(data)]
		d := data[(4+i*4)%len(data)]
		peer := peers[int(b)%len(peers)]
		hash := testBlobTxHashes[int(c)%len(testBlobTxHashes)]

		switch a % 7 {
		case 0:
			if fetcher.Notify(peer, []common.Hash{hash}, types.CustodyBitmapAll) == nil {
				mainnetWait(t, step)
			}
		case 1:
			if fetcher.Notify(peer, []common.Hash{hash}, frontCustody) == nil {
				mainnetWait(t, step)
			}
		case 2:
			if req, ok := mainnetPick(fetcher, b); ok {
				hashes, cells := mainnetResponse(req, d)
				if fetcher.Enqueue(req.peer, hashes, cells, req.mask) == nil {
					mainnetWait(t, step)
				}
			}
		case 3:
			if fetcher.Drop(peer) == nil {
				mainnetWait(t, step)
			}
		case 4:
			if len(fetcher.requests) > 0 {
				clock.Run(blobFetchTimeout + time.Millisecond)
				time.Sleep(time.Millisecond)
				mainnetDrain(step)
			}
		case 5:
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_ = fetcher.Notify(peer, []common.Hash{hash}, types.CustodyBitmapAll)
			}()
			go func() {
				defer wg.Done()
				_ = fetcher.Drop(peers[(int(b)+1)%len(peers)])
			}()
			wg.Wait()
			mainnetWait(t, step)
			mainnetWait(t, step)
		case 6:
			hashes := []common.Hash{hash, hash, testBlobTxHashes[(int(c)+1)%len(testBlobTxHashes)]}
			if fetcher.Notify(peer, hashes, types.CustodyBitmapAll) == nil {
				mainnetWait(t, step)
			}
		}
		mainnetDrain(step)
		mainnetAssert(t, fetcher)
	}
}

func TestBlobFetcherCurrentMainnetMatrix(t *testing.T) {
	for i := 0; i < 192; i++ {
		seed := []byte{byte(i), byte(i * 3), byte(i * 5), byte(i * 7), byte(i * 11), byte(i * 13), byte(i * 17), byte(i * 19)}
		t.Run(string(rune(i+1)), func(t *testing.T) { runMainnetMachine(t, seed) })
	}
}

func FuzzBlobFetcherCurrentMainnet(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0})
	f.Add([]byte{5, 1, 2, 3, 6, 2, 3, 4, 3, 1, 0, 0})
	f.Add([]byte{1, 0, 0, 0, 0, 1, 1, 0, 2, 0, 0, 5})
	f.Fuzz(func(t *testing.T, data []byte) { runMainnetMachine(t, data) })
}
