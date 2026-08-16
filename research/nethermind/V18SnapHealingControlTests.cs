// SPDX-FileCopyrightText: 2026 ZeroDayBugs research
// SPDX-License-Identifier: LGPL-3.0-only

using System.Threading.Tasks;
using Autofac;
using Nethermind.Core;
using Nethermind.Core.Collections;
using Nethermind.Core.Crypto;
using Nethermind.Core.Test;
using Nethermind.Core.Test.Builders;
using Nethermind.State;
using Nethermind.State.Snap;
using Nethermind.Synchronization.FastSync;
using Nethermind.Synchronization.SnapSync;
using Nethermind.Trie;
using NUnit.Framework;

namespace Nethermind.Synchronization.Test.FastSync;

[TestFixture]
public class V18SnapHealingControlTests : StateSyncFeedTestsBase
{
    [Test]
    public async Task Swapped_refresh_roots_are_repaired_before_state_sync_finalizes()
    {
        RemoteDbContext remote = new(_logManager);
        Address addressA = TestItem.AddressA;
        Address addressB = TestItem.AddressB;
        Hash256 accountPathA = Keccak.Compute(addressA.Bytes);
        Hash256 accountPathB = Keccak.Compute(addressB.Bytes);

        StorageTree storageA = SetStorage(remote.TrieStore, 4, addressA);
        StorageTree storageB = SetStorage(remote.TrieStore, 7, addressB);

        Account canonicalA = Build.An.Account
            .WithNonce(1)
            .WithStorageRoot(storageA.RootHash)
            .TestObject;
        Account canonicalB = Build.An.Account
            .WithNonce(2)
            .WithStorageRoot(storageB.RootHash)
            .TestObject;

        remote.StateTree.Set(addressA, canonicalA);
        remote.StateTree.Set(addressB, canonicalB);
        remote.StateTree.Commit();

        byte[] rootNodeA = remote.TrieStore.LoadRlp(accountPathA, TreePath.Empty, storageA.RootHash)!;
        byte[] rootNodeB = remote.TrieStore.LoadRlp(accountPathB, TreePath.Empty, storageB.RootHash)!;
        Assert.Multiple(() =>
        {
            Assert.That(rootNodeA, Is.Not.Null.And.Not.Empty);
            Assert.That(rootNodeB, Is.Not.Null.And.Not.Empty);
            Assert.That(storageA.RootHash, Is.Not.EqualTo(storageB.RootHash));
        });

        await using IContainer container = PrepareDownloader(remote);
        IStateSyncTestOperation local = container.Resolve<IStateSyncTestOperation>();

        // Account-range sync has already written the canonical account bodies, but the
        // storage-root node refresh below is controlled by a malicious snap/1 peer.
        local.SetAccountsAndCommit((accountPathA, canonicalA), (accountPathB, canonicalB));
        local.DeleteStateRoot();

        PathWithAccount pathA = new(accountPathA, canonicalA);
        PathWithAccount pathB = new(accountPathB, canonicalB);
        using AccountsToRefreshRequest request = new()
        {
            RootHash = remote.StateTree.RootHash,
            Paths = new ArrayPoolList<AccountWithStorageStartingHash>(2)
            {
                new() { PathAndAccount = pathA },
                new() { PathAndAccount = pathB },
            },
        };
        using IByteArrayList response = new ByteArrayListAdapter(
            new ArrayPoolList<byte[]>(2) { rootNodeB, rootNodeA });

        container.Resolve<ISnapProvider>().RefreshAccounts(request, response);

        Assert.Multiple(() =>
        {
            Assert.That(pathA.Account.StorageRoot, Is.EqualTo(storageB.RootHash));
            Assert.That(pathB.Account.StorageRoot, Is.EqualTo(storageA.RootHash));
        });

        // Mirror the snap storage downloader persisting the peer-selected roots under the
        // requested account namespaces. The final state-healing round must not trust them.
        INodeStorage localNodeStorage = container.Resolve<INodeStorage>();
        localNodeStorage.Set(accountPathA, TreePath.Empty, storageB.RootHash, rootNodeB);
        localNodeStorage.Set(accountPathB, TreePath.Empty, storageA.RootHash, rootNodeA);

        StateSyncPivot pivot = container.Resolve<StateSyncPivot>();
        pivot.UpdatedStorages.Add(accountPathA);
        pivot.UpdatedStorages.Add(accountPathB);

        SafeContext context = container.Resolve<SafeContext>();
        await ActivateAndWait(context);

        local.CompareTrees(remote, _logger, "END");
        Assert.Multiple(() =>
        {
            Assert.That(localNodeStorage.KeyExists(accountPathA, TreePath.Empty, storageA.RootHash), Is.True);
            Assert.That(localNodeStorage.KeyExists(accountPathB, TreePath.Empty, storageB.RootHash), Is.True);
        });
    }
}
