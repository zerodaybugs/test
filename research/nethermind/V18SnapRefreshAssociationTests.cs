// SPDX-FileCopyrightText: 2026 ZeroDayBugs research
// SPDX-License-Identifier: LGPL-3.0-only

using Autofac;
using Nethermind.Core;
using Nethermind.Core.Collections;
using Nethermind.Core.Crypto;
using Nethermind.Core.Test;
using Nethermind.Core.Test.Builders;
using Nethermind.State.Snap;
using Nethermind.Synchronization.SnapSync;
using NUnit.Framework;

namespace Nethermind.Synchronization.Test.SnapSync;

[TestFixture]
public class V18SnapRefreshAssociationTests
{
    [Test]
    public void RefreshAccounts_accepts_swapped_storage_root_nodes_by_response_position()
    {
        using IContainer container = new ContainerBuilder()
            .AddModule(new TestSynchronizerModule(new TestSyncConfig()))
            .Build();

        SnapProvider provider = container.Resolve<SnapProvider>();

        byte[] storageRootNodeA = [0xc1, 0x80];
        byte[] storageRootNodeB = [0xc2, 0x81, 0x01];
        Hash256 storageRootA = Keccak.Compute(storageRootNodeA);
        Hash256 storageRootB = Keccak.Compute(storageRootNodeB);

        PathWithAccount accountA = new(
            TestItem.KeccakA,
            Build.An.Account.WithNonce(1).WithStorageRoot(storageRootA).TestObject);
        PathWithAccount accountB = new(
            TestItem.KeccakB,
            Build.An.Account.WithNonce(2).WithStorageRoot(storageRootB).TestObject);

        using AccountsToRefreshRequest request = new()
        {
            RootHash = TestItem.KeccakC,
            Paths = new ArrayPoolList<AccountWithStorageStartingHash>(2)
            {
                new() { PathAndAccount = accountA },
                new() { PathAndAccount = accountB },
            },
        };

        // A malicious snap/1 peer returns valid root-node RLPs in the opposite order.
        using IByteArrayList response = new ByteArrayListAdapter(
            new byte[][] { storageRootNodeB, storageRootNodeA }.ToPooledList());

        provider.RefreshAccounts(request, response);

        Assert.Multiple(() =>
        {
            Assert.That(accountA.Account.StorageRoot, Is.EqualTo(storageRootB));
            Assert.That(accountB.Account.StorageRoot, Is.EqualTo(storageRootA));
            Assert.That(accountA.Account.StorageRoot, Is.Not.EqualTo(storageRootA));
            Assert.That(accountB.Account.StorageRoot, Is.Not.EqualTo(storageRootB));
        });
    }

    [Test]
    public void RefreshAccounts_accepts_unrelated_node_hash_as_account_storage_root()
    {
        using IContainer container = new ContainerBuilder()
            .AddModule(new TestSynchronizerModule(new TestSyncConfig()))
            .Build();

        SnapProvider provider = container.Resolve<SnapProvider>();

        Hash256 originalRoot = TestItem.KeccakD;
        byte[] attackerChosenNode = [0xc4, 0x83, 0xde, 0xad, 0xbe];
        Hash256 attackerChosenRoot = Keccak.Compute(attackerChosenNode);

        PathWithAccount account = new(
            TestItem.KeccakA,
            Build.An.Account.WithNonce(1).WithStorageRoot(originalRoot).TestObject);

        using AccountsToRefreshRequest request = new()
        {
            RootHash = TestItem.KeccakC,
            Paths = new ArrayPoolList<AccountWithStorageStartingHash>(1)
            {
                new() { PathAndAccount = account },
            },
        };

        using IByteArrayList response = new ByteArrayListAdapter(
            new byte[][] { attackerChosenNode }.ToPooledList());

        provider.RefreshAccounts(request, response);

        Assert.That(account.Account.StorageRoot, Is.EqualTo(attackerChosenRoot));
        Assert.That(account.Account.StorageRoot, Is.Not.EqualTo(originalRoot));
    }
}
