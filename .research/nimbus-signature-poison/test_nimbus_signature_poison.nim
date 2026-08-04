{.push raises: [].}
{.used.}

import
  std/[os, sets],
  unittest2,
  results,
  kzg4844/[kzg, kzg_abi],
  ssz_serialization/types,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/spec/[forks, helpers, column_map, peerdas_helpers],
  ../beacon_chain/spec/datatypes/[deneb, fulu],
  ../beacon_chain/sync/request_manager

from std/strutils import rsplit

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert loadTrustedSetup(
    sourceDir &
      "/../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 7).isOk

proc canonicalBlob(): KzgBlob =
  var raw: array[int(BYTES_PER_BLOB), byte]
  for i in 0 ..< int(FIELD_ELEMENTS_PER_BLOB):
    let value = uint16((i * 257 + 17) mod 65521)
    raw[i * int(BYTES_PER_FIELD_ELEMENT) + 30] = byte(value shr 8)
    raw[i * int(BYTES_PER_FIELD_ELEMENT) + 31] = byte(value)
  KzgBlob(bytes: raw)

proc makeValidSidecar(): ref fulu.DataColumnSidecar =
  let
    blob = canonicalBlob()
    commitment = blobToKzgCommitment(blob).valueOr:
      raiseAssert "blobToKzgCommitment failed"
    cp = computeCellsAndKzgProofs(blob).valueOr:
      raiseAssert "computeCellsAndKzgProofs failed"

  var
    signedBlock: fulu.SignedBeaconBlock
    proofs = newSeq[KzgProof](int(CELLS_PER_EXT_BLOB))
    requestedColumns: ColumnMap

  signedBlock.message.slot = Slot(1)
  signedBlock.message.proposer_index = ValidatorIndex(0)
  signedBlock.message.body.blob_kzg_commitments =
    KzgCommitments.init(@[commitment])
  signedBlock.signature.blob[0] = 0x11'u8

  for i in 0 ..< int(CELLS_PER_EXT_BLOB):
    proofs[i] = cp.proofs[i]
  requestedColumns.incl(ColumnIndex(0))

  let sidecars = assemble_data_column_sidecars(
    signedBlock, @[blob], proofs, requestedColumns)
  doAssert sidecars.len == 1
  sidecars[0]

suite "Nimbus v26.7.0 req/resp sidecar signature persistence":
  test "invalid sidecar signature passes response checks and survives DB roundtrip":
    let validSidecar = makeValidSidecar()
    let blockRoot = hash_tree_root(validSidecar[].signed_block_header.message)

    var poisoned = new(fulu.DataColumnSidecar)
    poisoned[] = validSidecar[]
    poisoned[].signed_block_header.signature.blob[0] =
      validSidecar[].signed_block_header.signature.blob[0] xor 0xff'u8

    check:
      poisoned[].signed_block_header.signature !=
        validSidecar[].signed_block_header.signature
      hash_tree_root(poisoned[].signed_block_header.message) == blockRoot
      poisoned[].verify_data_column_sidecar_inclusion_proof().isOk
      poisoned[].verify_data_column_sidecar_kzg_proofs().isOk

    var ids = initHashSet[DataColumnsByRootIdentifier]()
    ids.incl DataColumnsByRootIdentifier(
      block_root: blockRoot,
      indices: DataColumnIndices(@[ColumnIndex(0)]))

    let accepted = checkColumnResponse(ids, @[poisoned])
    check:
      accepted.isSome
      accepted.get().len == 1
      accepted.get()[0].block_root == blockRoot
      accepted.get()[0].sidecar[].signed_block_header.signature ==
        poisoned[].signed_block_header.signature

    let db = BeaconChainDB.new("", defaultRuntimeConfig, inMemory = true)
    defer: db.close()
    db.putDataColumnSidecars(@[poisoned])

    var persisted: fulu.DataColumnSidecar
    check:
      db.getDataColumnSidecar(blockRoot, ColumnIndex(0), persisted)
      persisted.signed_block_header.signature ==
        poisoned[].signed_block_header.signature
      persisted.signed_block_header.signature !=
        validSidecar[].signed_block_header.signature
      persisted.verify_data_column_sidecar_inclusion_proof().isOk
      persisted.verify_data_column_sidecar_kzg_proofs().isOk

    var wireBytes: seq[byte]
    check:
      db.getDataColumnSidecarSZ(
        ConsensusFork.Fulu, blockRoot, ColumnIndex(0), wireBytes)
      wireBytes.len > 0

    echo "RESULT=PASS signature_checked_by_response=false persisted_invalid_signature=true reservice_bytes=true"

doAssert freeTrustedSetup().isOk
