/*
 * SPDX-License-Identifier: Apache-2.0
 */
package tech.pegasys.teku.storage.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.datastructures.blocks.SignedBlockAndState;
import tech.pegasys.teku.spec.util.DataStructureUtil;

class V19FuluDaTimelinessTest {
  @Test
  void fuluMustNotRecordBodyArrivalAsTimelyBeforeDataAvailabilityCompletes() {
    final UInt64 slot = UInt64.valueOf(10);
    final Spec spec = TestSpecFactory.createMinimalFulu();
    final DataStructureUtil data = new DataStructureUtil(spec);
    final SignedBlockAndState block = data.randomSignedBlockAndState(slot);
    final UInt64 genesisMillis = block.getState().getGenesisTime().times(1000);
    final BlockTimelinessTracker tracker =
        new BlockTimelinessTracker(spec, () -> genesisMillis, new HashMap<>());

    final UInt64 bodyArrivalMillis =
        genesisMillis
            .plus(slot.times(spec.getGenesisSpecConfig().getSlotDurationMillis()))
            .plus(100);

    // Normative Fulu on_block records timeliness only after DA succeeds. A body-arrival
    // callback before DA must therefore leave the tracker empty.
    tracker.setBlockTimelinessFromArrivalTime(block.getBlock(), bodyArrivalMillis);

    assertThat(tracker.getBlockTimeliness(block.getRoot())).isEmpty();
  }
}
