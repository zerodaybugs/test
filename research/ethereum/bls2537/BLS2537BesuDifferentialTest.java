package org.hyperledger.besu.evm.precompile;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.precompile.PrecompiledContract.PrecompileContractResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/** Executes a shared EIP-2537 corpus through the exact Besu 26.7.1 native precompiles. */
@SuppressWarnings({"StringSplitter", "SystemOut"})
class BLS2537BesuDifferentialTest {
  private static final MessageFrame FRAME = mock(MessageFrame.class);

  @Test
  void executeSharedCorpus() throws Exception {
    assertTrue(AbstractBLS12PrecompiledContract.isAvailable(), "BLS2537_BESU_NATIVE_UNAVAILABLE");
    AbstractBLS12PrecompiledContract.setPrecompileCaching(false);

    final Path corpus = Path.of(requiredEnvironment("BLS2537_CORPUS_FILE"));
    final Path output = Path.of(requiredEnvironment("BLS2537_RESULT_FILE"));
    if (output.getParent() != null) {
      Files.createDirectories(output.getParent());
    }

    final Map<String, PrecompiledContract> operations = new LinkedHashMap<>();
    operations.put("G1ADD", new BLS12G1AddPrecompiledContract());
    operations.put("G1MSM", new BLS12G1MultiExpPrecompiledContract());
    operations.put("G2ADD", new BLS12G2AddPrecompiledContract());
    operations.put("G2MSM", new BLS12G2MultiExpPrecompiledContract());
    operations.put("PAIRING", new BLS12PairingPrecompiledContract());
    operations.put("MAP_FP_G1", new BLS12MapFpToG1PrecompiledContract());
    operations.put("MAP_FP2_G2", new BLS12MapFp2ToG2PrecompiledContract());

    final List<String> results = new ArrayList<>();
    int count = 0;
    for (String line : Files.readAllLines(corpus, StandardCharsets.US_ASCII)) {
      if (line.isBlank()) {
        continue;
      }
      final String[] fields = line.split("\\t", 3);
      if (fields.length != 3) {
        throw new IllegalArgumentException("BLS2537_INVALID_CORPUS_ROW");
      }
      final PrecompiledContract operation = operations.get(fields[1]);
      if (operation == null) {
        throw new IllegalArgumentException("BLS2537_UNKNOWN_OPERATION");
      }
      final Bytes input = Bytes.fromHexString(fields[2]);
      final PrecompileContractResult result = operation.computePrecompile(input, FRAME);
      final String normalized;
      if (result.state() == MessageFrame.State.COMPLETED_SUCCESS) {
        normalized = "OK:" + result.output().toUnprefixedHexString();
      } else {
        normalized = "ERR";
      }
      results.add(fields[0] + "\t" + fields[1] + "\t" + normalized);
      count++;
    }

    Files.write(
        output,
        results,
        StandardCharsets.US_ASCII,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE);
    System.out.printf("BLS2537_BESU_COMPLETE cases=%d%n", count);
  }

  private static String requiredEnvironment(final String key) {
    final String value = System.getenv(key);
    if (value == null || value.isBlank()) {
      throw new IllegalStateException("BLS2537_MISSING_ENVIRONMENT_" + key);
    }
    return value;
  }
}
