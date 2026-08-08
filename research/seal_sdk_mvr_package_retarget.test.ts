// Exact regression test fragment for MystenLabs/ts-sdks @ 5fd97fb14fd15d96735064abe52522627b8c0358.
// Local/offline only. No network writes.

import { describe, expect, it } from 'vitest';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SessionKey } from '../../src/session-key.js';
import type { SealCompatibleClient } from '../../src/types.js';

describe('Seal MVR certificate package retarget', () => {
	it('preserves one wallet certificate while packageId is changed on import', async () => {
		const packageA = '0x1111111111111111111111111111111111111111111111111111111111111111';
		const packageB = '0x2222222222222222222222222222222222222222222222222222222222222222';
		const mvrName = '@zdb/seal-cross-network-regression';
		const wallet = Ed25519Keypair.generate();
		const delegatedSession = Ed25519Keypair.generate();
		const client = {} as SealCompatibleClient;
		const creationTimeMs = Date.now();
		const ttlMin = 10;

		// Construct the package-A session state and obtain the exact wallet message.
		const unsignedA = SessionKey.import(
			{
				address: wallet.getPublicKey().toSuiAddress(),
				packageId: packageA,
				mvrName,
				creationTimeMs,
				ttlMin,
				sessionKey: delegatedSession.getSecretKey(),
			},
			client,
		);
		const walletMessage = unsignedA.getPersonalMessage();
		const { signature } = await wallet.signPersonalMessage(walletMessage);

		const signedExport = {
			...unsignedA.export(),
			personalMessageSignature: signature,
		};
		const restoredA = SessionKey.import(signedExport, client);

		// Only packageId is changed. The MVR name, wallet signature, delegated
		// session private key, creation time and TTL remain byte-for-byte identical.
		const restoredB = SessionKey.import(
			{
				...signedExport,
				packageId: packageB,
			},
			client,
		);

		const certA = await restoredA.getCertificate();
		const certB = await restoredB.getCertificate();

		expect(restoredA.getPackageId()).toBe(packageA);
		expect(restoredB.getPackageId()).toBe(packageB);
		expect(restoredB.getPersonalMessage()).toEqual(restoredA.getPersonalMessage());
		expect(certB).toEqual(certA);
		expect(restoredB.export().sessionKey).toBe(restoredA.export().sessionKey);

		console.log(
			`SEAL_SDK_MVR_PACKAGE_RETARGET_PASS package_a=${packageA} package_b=${packageB} mvr_name=${mvrName} certificate_equal=true session_secret_equal=true`,
		);
	});
});
