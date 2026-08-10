package org.hyperledger.besu.evm.precompile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.hyperledger.besu.crypto.SECP256R1;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.OsakaGasCalculator;
import org.hyperledger.besu.evm.precompile.PrecompiledContract.PrecompileContractResult;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.SplittableRandom;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Redacted consensus differential gate for EIP-7951 P256VERIFY.
 *
 * <p>The production BoringSSL path, BesuNativeEC/libsecp256r1 path and pure Java/BouncyCastle path
 * must return exactly the same output for every input. Exact candidate bytes are written only to a
 * workflow-local evidence file, while the thrown assertion contains a generic marker.
 */
class P256NativeJavaRedactedDifferentialTest {
  private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");
  private static final BigInteger N = CURVE.getN();
  private static final BigInteger P = CURVE.getCurve().getField().getCharacteristic();
  private static final ECDomainParameters DOMAIN =
      new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), N, CURVE.getH());

  private static final MessageFrame FRAME = mock(MessageFrame.class);
  private static P256VerifyPrecompiledContract javaVerifier;
  private static P256VerifyPrecompiledContract besuNativeVerifier;
  private static boolean besuNativeAvailable;
  private static Path evidencePath;

  @BeforeAll
  static void setup() throws Exception {
    final String configuredEvidence = System.getenv("P256_EVIDENCE_FILE");
    evidencePath =
        Path.of(
            configuredEvidence == null || configuredEvidence.isBlank()
                ? "build/p256-candidate-evidence.txt"
                : configuredEvidence);
    if (evidencePath.getParent() != null) {
      Files.createDirectories(evidencePath.getParent());
    }

    final SECP256R1 javaAlgorithm = new SECP256R1();
    javaAlgorithm.disableNative();
    assertFalse(javaAlgorithm.isNative(), "P256_GATE_INCONCLUSIVE_JAVA_ORACLE_IS_NATIVE");

    final SECP256R1 nativeAlgorithm = new SECP256R1();
    besuNativeAvailable = nativeAlgorithm.maybeEnableNative();

    javaVerifier = new P256VerifyPrecompiledContract(new OsakaGasCalculator(), javaAlgorithm);
    besuNativeVerifier =
        new P256VerifyPrecompiledContract(new OsakaGasCalculator(), nativeAlgorithm);

    assertTrue(
        P256VerifyPrecompiledContract.maybeEnableNativeBoringSSL(),
        "P256_GATE_INCONCLUSIVE_BORINGSSL_UNAVAILABLE");
    P256VerifyPrecompiledContract.disableNativeBoringSSL();

    System.out.printf(
        "P256_DIFF_ENV boring_ssl=true besu_native_ec=%s java_native=false%n",
        besuNativeAvailable);
  }

  @AfterAll
  static void restoreNative() {
    P256VerifyPrecompiledContract.maybeEnableNativeBoringSSL();
  }

  @Test
  void deterministicValidAndMutationCorpusHasIdenticalConsensusOutput() throws Exception {
    final int validSeeds = 25_000;
    long cases = 0;

    for (int seed = 1; seed <= validSeeds; seed++) {
      final byte[] canonical = deterministicSignature(seed);
      compareAll(canonical, "valid-" + seed);
      cases++;

      final byte[] highS = canonical.clone();
      put32(highS, 64, N.subtract(read32(highS, 64)));
      compareAll(highS, "high-s-" + seed);
      cases++;

      final byte[] negatedY = canonical.clone();
      put32(negatedY, 128, P.subtract(read32(negatedY, 128)).mod(P));
      compareAll(negatedY, "negated-y-" + seed);
      cases++;

      for (int component = 0; component < 5; component++) {
        final byte[] bitFlip = canonical.clone();
        final int offset = component * 32;
        final int byteIndex = Math.floorMod(seed * 17 + component * 11, 32);
        final int bitIndex = Math.floorMod(seed + component * 3, 8);
        bitFlip[offset + byteIndex] ^= (byte) (1 << bitIndex);
        compareAll(bitFlip, "bitflip-" + seed + "-" + component);
        cases++;
      }
    }

    System.out.printf("P256_DIFF_VALID_MUTATION_PASS cases=%d%n", cases);
  }

  @Test
  void structuredBoundaryGridHasIdenticalConsensusOutput() throws Exception {
    final byte[] base = deterministicSignature(0x7951);
    final BigInteger[] scalarValues = {
      BigInteger.ZERO,
      BigInteger.ONE,
      N.subtract(BigInteger.ONE),
      N,
      N.add(BigInteger.ONE),
      BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
    };
    final BigInteger[] coordinateValues = {
      BigInteger.ZERO,
      BigInteger.ONE,
      P.subtract(BigInteger.ONE),
      P,
      P.add(BigInteger.ONE),
      BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
    };

    long cases = 0;
    for (int component : new int[] {32, 64}) {
      for (BigInteger value : scalarValues) {
        final byte[] input = base.clone();
        put32(input, component, value);
        compareAll(input, "scalar-boundary-" + component + "-" + value.toString(16));
        cases++;
      }
    }
    for (int component : new int[] {96, 128}) {
      for (BigInteger value : coordinateValues) {
        final byte[] input = base.clone();
        put32(input, component, value);
        compareAll(input, "coordinate-boundary-" + component + "-" + value.toString(16));
        cases++;
      }
    }

    final byte[][] special = {
      new byte[160],
      replacePoint(base, BigInteger.ZERO, BigInteger.ZERO),
      replacePoint(base, P, P),
      replacePoint(base, P.add(BigInteger.ONE), P.add(BigInteger.ONE)),
      replacePoint(
          base,
          BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE),
          BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE))
    };
    for (int i = 0; i < special.length; i++) {
      compareAll(special[i], "special-" + i);
      cases++;
    }

    System.out.printf("P256_DIFF_BOUNDARY_PASS cases=%d%n", cases);
  }

  @Test
  void deterministicRawCorpusHasIdenticalConsensusOutput() {
    final int rawCases = 500_000;
    final SplittableRandom random = new SplittableRandom(0x7951_2026_0810L);
    final byte[] input = new byte[160];

    for (int i = 0; i < rawCases; i++) {
      for (int offset = 0; offset < input.length; offset += 8) {
        ByteBuffer.wrap(input, offset, 8).putLong(random.nextLong());
      }
      compareAll(input, "raw-" + i);
    }

    System.out.printf("P256_DIFF_RAW_PASS cases=%d%n", rawCases);
  }

  @Test
  void invalidLengthsHaveIdenticalOutputAndFixedGas() {
    for (int length : new int[] {0, 1, 31, 32, 64, 96, 128, 159, 161, 192, 1024}) {
      final byte[] input = new byte[length];
      Arrays.fill(input, (byte) 0xA5);
      compareAll(input, "length-" + length);
      assertEquals(6_900L, javaVerifier.gasRequirement(Bytes.wrap(input)));
    }
    System.out.println("P256_DIFF_LENGTH_PASS cases=11");
  }

  private static void compareAll(final byte[] rawInput, final String label) {
    final byte[] input = rawInput.clone();
    final Bytes bytes = Bytes.wrap(input);

    P256VerifyPrecompiledContract.maybeEnableNativeBoringSSL();
    final PrecompileContractResult boring =
        besuNativeVerifier.computePrecompile(bytes, FRAME);

    P256VerifyPrecompiledContract.disableNativeBoringSSL();
    final PrecompileContractResult javaResult = javaVerifier.computePrecompile(bytes, FRAME);
    final PrecompileContractResult besuNativeResult =
        besuNativeVerifier.computePrecompile(bytes, FRAME);

    final boolean boringMismatch = !javaResult.output().equals(boring.output());
    final boolean besuNativeMismatch =
        besuNativeAvailable && !javaResult.output().equals(besuNativeResult.output());
    if (!boringMismatch && !besuNativeMismatch) {
      return;
    }

    final String evidence =
        "label="
            + label
            + System.lineSeparator()
            + "input="
            + bytes.toHexString()
            + System.lineSeparator()
            + "boring="
            + boring.output().toHexString()
            + System.lineSeparator()
            + "java="
            + javaResult.output().toHexString()
            + System.lineSeparator()
            + "besuNative="
            + besuNativeResult.output().toHexString()
            + System.lineSeparator()
            + "besuNativeAvailable="
            + besuNativeAvailable
            + System.lineSeparator();
    writeEvidence(evidence);
    throw new AssertionError("P256_CONSENSUS_DIFFERENTIAL_CANDIDATE");
  }

  private static synchronized void writeEvidence(final String evidence) {
    try {
      Files.writeString(
          evidencePath,
          evidence,
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);
    } catch (IOException e) {
      throw new AssertionError("P256_GATE_INCONCLUSIVE_EVIDENCE_WRITE_FAILURE");
    }
  }

  private static byte[] deterministicSignature(final int seed) throws Exception {
    final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    final byte[] seedBytes = ByteBuffer.allocate(8).putLong(seed & 0xffff_ffffL).array();
    final byte[] privateDigest = sha256.digest(concat("P256-KEY".getBytes(), seedBytes));
    final BigInteger d =
        new BigInteger(1, privateDigest).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    final byte[] hash = sha256.digest(concat("P256-MSG".getBytes(), seedBytes));

    final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(true, new ECPrivateKeyParameters(d, DOMAIN));
    final BigInteger[] signature = signer.generateSignature(hash);

    final ECPoint q = CURVE.getG().multiply(d).normalize();
    final byte[] output = new byte[160];
    System.arraycopy(hash, 0, output, 0, 32);
    put32(output, 32, signature[0]);
    put32(output, 64, signature[1]);
    put32(output, 96, q.getAffineXCoord().toBigInteger());
    put32(output, 128, q.getAffineYCoord().toBigInteger());
    return output;
  }

  private static byte[] replacePoint(
      final byte[] base, final BigInteger x, final BigInteger y) {
    final byte[] output = base.clone();
    put32(output, 96, x);
    put32(output, 128, y);
    return output;
  }

  private static BigInteger read32(final byte[] input, final int offset) {
    return new BigInteger(1, Arrays.copyOfRange(input, offset, offset + 32));
  }

  private static void put32(final byte[] target, final int offset, final BigInteger value) {
    final byte[] raw = value.mod(BigInteger.ONE.shiftLeft(256)).toByteArray();
    final int sourceOffset = raw.length > 32 ? raw.length - 32 : 0;
    final int sourceLength = Math.min(raw.length, 32);
    Arrays.fill(target, offset, offset + 32, (byte) 0);
    System.arraycopy(raw, sourceOffset, target, offset + 32 - sourceLength, sourceLength);
  }

  private static byte[] concat(final byte[] left, final byte[] right) {
    final byte[] output = Arrays.copyOf(left, left.length + right.length);
    System.arraycopy(right, 0, output, left.length, right.length);
    return output;
  }
}
