package io.github.astrapi69.crypt.data.factory;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyAgreementFactory {

	public static SecretKey newSharedSecret(
			PrivateKey privateKey,
			PublicKey publicKey,
			String keyAgreementAlgorithm,
			String secretKeyAlgorithm,
			String provider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {

		KeyAgreement keyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm, provider);
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(publicKey, true);

		return keyAgreement.generateSecret(secretKeyAlgorithm);
	}
}
