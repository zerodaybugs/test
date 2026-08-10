/*
 * Private research harness for Besu 26.7.1.
 * Demonstrates remaining Address hash-collision behavior in the default STACKED world updater.
 */
package org.hyperledger.besu.evm.worldstate;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.internal.EvmConfiguration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class WorldUpdaterHashDosBenchmarkTest {

  private static final int[] COUNTS = {500, 1_000, 2_000, 4_000, 8_000, 12_000};

  private static final class RootUpdater extends AbstractWorldUpdater<WorldView, Account> {
    RootUpdater() {
      super(WorldView.EMPTY, EvmConfiguration.DEFAULT);
    }

    @Override
    protected Account getForMutation(final Address address) {
      return null;
    }

    @Override
    public Collection<? extends Account> getTouchedAccounts() {
      return getUpdatedAccounts();
    }

    @Override
    public Collection<Address> getDeletedAccountAddresses() {
      return getDeletedAccounts();
    }

    @Override
    public void revert() {
      reset();
    }

    @Override
    public void commit() {
      // Root harness: no backing trie is required for measuring in-memory update tracking.
    }
  }

  private static void writeZeroSumPair(final byte[] bytes, final int offset, final int digit) {
    switch (digit) {
      case 0 -> {
        bytes[offset] = 0;
        bytes[offset + 1] = 0;
      }
      case 1 -> {
        bytes[offset] = 1;
        bytes[offset + 1] = (byte) -31;
      }
      default -> {
        bytes[offset] = (byte) -1;
        bytes[offset + 1] = 31;
      }
    }
  }

  private static Address collidingAddress(final long index) {
    final byte[] bytes = new byte[Address.SIZE];
    long remaining = index;
    for (int pair = 0; pair < Address.SIZE / 2; pair++) {
      writeZeroSumPair(bytes, pair * 2, (int) (remaining % 3));
      remaining /= 3;
    }
    return Address.wrap(Bytes.wrap(bytes));
  }

  private static Address controlAddress(final long index) {
    final byte[] bytes = new byte[Address.SIZE];
    long x = index + 0x9e3779b97f4a7c15L;
    for (int i = 0; i < bytes.length; i++) {
      x ^= x >>> 12;
      x ^= x << 25;
      x ^= x >>> 27;
      x *= 0x2545F4914F6CDD1DL;
      bytes[i] = (byte) x;
    }
    return Address.wrap(Bytes.wrap(bytes));
  }

  private static List<Address> addresses(final int count, final boolean colliding) {
    final List<Address> result = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      result.add(colliding ? collidingAddress(i) : controlAddress(i));
    }
    return result;
  }

  private static long exerciseDefaultStackedUpdater(
      final List<Address> addresses, final boolean commitLayers) {
    final RootUpdater root = new RootUpdater();
    final WorldUpdater transactionUpdater = root.updater();
    final WorldUpdater frameUpdater = transactionUpdater.updater();

    final long started = System.nanoTime();
    for (final Address address : addresses) {
      frameUpdater.getOrCreate(address).incrementBalance(Wei.ZERO);
    }
    if (commitLayers) {
      frameUpdater.commit();
      transactionUpdater.commit();
    }
    return System.nanoTime() - started;
  }

  @Test
  void benchmarkRemainingWorldUpdaterCollisionPath() {
    final int expectedHash = collidingAddress(0).hashCode();
    for (int i = 1; i < 500; i++) {
      assertThat(collidingAddress(i).hashCode()).isEqualTo(expectedHash);
      assertThat(collidingAddress(i)).isNotEqualTo(collidingAddress(0));
    }

    // JIT warm-up on independent updater instances.
    exerciseDefaultStackedUpdater(addresses(300, false), true);
    exerciseDefaultStackedUpdater(addresses(300, true), true);

    System.out.println("BESU_WORLD_UPDATER_HASHDOS_BENCHMARK_V1");
    System.out.println("mode=STACKED path=frame.getOrCreate+commit_to_tx+commit_to_root");
    System.out.println("count,control_ms,colliding_ms,ratio");

    double lastRatio = 0.0;
    for (final int count : COUNTS) {
      final List<Address> controls = addresses(count, false);
      final List<Address> collisions = addresses(count, true);
      final long controlNs = exerciseDefaultStackedUpdater(controls, true);
      final long collisionNs = exerciseDefaultStackedUpdater(collisions, true);
      final double ratio = (double) collisionNs / Math.max(1L, controlNs);
      lastRatio = ratio;
      System.out.printf(
          "%d,%.3f,%.3f,%.2f%n",
          count,
          controlNs / 1_000_000.0,
          collisionNs / 1_000_000.0,
          ratio);
    }

    // This is a characterization gate, not a fixed wall-clock gate. It fails only when the
    // colliding path is not materially slower, which would kill the hypothesis.
    assertThat(lastRatio).isGreaterThan(3.0);
  }
}
