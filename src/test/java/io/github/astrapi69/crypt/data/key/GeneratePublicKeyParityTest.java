/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * Parity tests for {@link PrivateKeyExtensions#generatePublicKey(PrivateKey)}, and regression tests
 * for issue #25.
 * <p>
 * A private key carries everything its public counterpart is made of, so the two are one thing seen
 * from two sides. The method knew that for rsa alone and answered null for every other algorithm -
 * an answer that also meant "generation failed", so a caller could not tell the two apart.
 */
class GeneratePublicKeyParityTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static KeyPair newKeyPair(final String algorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("RSA".equals(algorithm) || "DSA".equals(algorithm))
		{
			generator.initialize(2048);
		}
		if ("DH".equals(algorithm))
		{
			generator.initialize(1024);
		}
		return generator.generateKeyPair();
	}

	/**
	 * The property, stated exactly: what is derived from the private key is the public key that was
	 * generated with it, byte for byte. Nothing weaker would do - a key of the right shape that
	 * belongs to a different private key would pass a looser assertion.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or the derivation fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "X448", "DH",
			"ML-DSA", "ML-KEM" })
	void theDerivedKeyIsTheOneTheKeyPairWasBornWith(final String algorithm) throws Exception
	{
		KeyPair keyPair = newKeyPair(algorithm);

		PublicKey derived = PrivateKeyExtensions.generatePublicKey(keyPair.getPrivate());

		assertArrayEquals(keyPair.getPublic().getEncoded(), derived.getEncoded(),
			algorithm + " must derive the public key it was generated with");
	}

	/**
	 * The curve travels with an ec key, so deriving has to stay on it - including the curves the
	 * jdk does not implement, which is where a wrong provider would show.
	 *
	 * @param curve
	 *            the named curve to generate on
	 * @throws Exception
	 *             if key generation or the derivation fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "secp256r1", "secp384r1", "secp521r1", "prime239v1", "secp256k1" })
	void anEcKeyIsDerivedOnItsOwnCurve(final String curve) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(new ECGenParameterSpec(curve));
		KeyPair keyPair = generator.generateKeyPair();

		PublicKey derived = PrivateKeyExtensions.generatePublicKey(keyPair.getPrivate());

		assertArrayEquals(keyPair.getPublic().getEncoded(), derived.getEncoded(),
			curve + " must derive the public key it was generated with");
	}

	/**
	 * The caller that felt this most: a key pair built from a private key alone had a null public
	 * half for everything but rsa, and nothing said so until something dereferenced it.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or the derivation fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519" })
	void aKeyPairBuiltFromAPrivateKeyHasBothHalves(final String algorithm) throws Exception
	{
		KeyPair generated = newKeyPair(algorithm);

		KeyPair rebuilt = KeyPairFactory.newKeyPair(generated.getPrivate());

		assertArrayEquals(generated.getPublic().getEncoded(), rebuilt.getPublic().getEncoded(),
			algorithm + " must come back with the public half it was generated with");
		assertArrayEquals(generated.getPrivate().getEncoded(), rebuilt.getPrivate().getEncoded());
	}

	/**
	 * What cannot be derived is said out loud, with the algorithm named, rather than answered with
	 * a null that also meant "it failed" and "there is none".
	 */
	@Test
	void whatCannotBeDerivedIsNamedRatherThanAnsweredWithNothing()
	{
		PrivateKey notAKnownKey = new PrivateKey()
		{
			@Override
			public String getAlgorithm()
			{
				return "NoSuchAlgorithmAtAll";
			}

			@Override
			public String getFormat()
			{
				return "PKCS#8";
			}

			@Override
			public byte[] getEncoded()
			{
				return new byte[] { 0x30, 0x00 };
			}
		};

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyExtensions.generatePublicKey(notAKnownKey));

		assertTrue(refused.getMessage().contains("NoSuchAlgorithmAtAll"),
			"the message must name the algorithm, but was: '" + refused.getMessage() + "'");
	}

	/**
	 * A key bouncy castle can read but whose public half it does not hand out is named, not
	 * answered with nothing. Slh-dsa is such a key: its private parameters carry the public key as
	 * bytes, and there is no public constructor to make parameters of them again.
	 *
	 * @throws Exception
	 *             if key generation fails
	 */
	@Test
	void aKeyWhosePublicHalfCannotBeDerivedIsNamed() throws Exception
	{
		KeyPair keyPair = newKeyPair("SLH-DSA");

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> PrivateKeyExtensions.generatePublicKey(keyPair.getPrivate()));

		assertTrue(refused.getMessage().contains("Derivable are"),
			"the message must say what can be derived, but was: '" + refused.getMessage() + "'");
	}

	/**
	 * A diffie-hellman key whose encoding cannot be reused still yields a public key: the algorithm
	 * identifier is what carries q and the validation parameters, and without it the plain p and g
	 * the key itself holds are what is left to build from.
	 *
	 * @throws Exception
	 *             if key generation or the derivation fails
	 */
	@Test
	void aDiffieHellmanKeyWithAnUnusableEncodingStillYieldsAPublicKey() throws Exception
	{
		KeyPair keyPair = newKeyPair("DH");
		DHPrivateKey generated = (DHPrivateKey)keyPair.getPrivate();
		DHPrivateKey withoutAUsableEncoding = new DHPrivateKey()
		{
			@Override
			public BigInteger getX()
			{
				return generated.getX();
			}

			@Override
			public DHParameterSpec getParams()
			{
				// the plain spec, not bouncy castle's domain spec, so there is no q to carry over
				return new DHParameterSpec(generated.getParams().getP(),
					generated.getParams().getG());
			}

			@Override
			public String getAlgorithm()
			{
				return "DH";
			}

			@Override
			public String getFormat()
			{
				return "PKCS#8";
			}

			@Override
			public byte[] getEncoded()
			{
				return new byte[] { 0x30, 0x00 };
			}
		};

		PublicKey derived = PrivateKeyExtensions.generatePublicKey(withoutAUsableEncoding);

		assertTrue(derived instanceof DHPublicKey, "a diffie-hellman public key must come back");
		assertEquals(
			generated.getParams().getG().modPow(generated.getX(), generated.getParams().getP()),
			((DHPublicKey)derived).getY(), "the public value must be g raised to x modulo p");
	}

	/** Nothing is not a key. */
	@Test
	void aMissingKeyIsRefusedOutright()
	{
		assertThrows(NullPointerException.class,
			() -> PrivateKeyExtensions.generatePublicKey(null));
	}

	/**
	 * The derived key is usable and not merely shaped right: it verifies what its private half
	 * signed.
	 *
	 * @throws Exception
	 *             if key generation, signing or verifying fails
	 */
	@Test
	void theDerivedKeyVerifiesWhatItsPrivateHalfSigned() throws Exception
	{
		KeyPair keyPair = newKeyPair("EC");
		PublicKey derived = PrivateKeyExtensions.generatePublicKey(keyPair.getPrivate());

		java.security.Signature signing = java.security.Signature.getInstance("SHA256withECDSA",
			BouncyCastleProvider.PROVIDER_NAME);
		signing.initSign(keyPair.getPrivate());
		signing.update("payload".getBytes());
		byte[] signature = signing.sign();

		java.security.Signature verifying = java.security.Signature.getInstance("SHA256withECDSA",
			BouncyCastleProvider.PROVIDER_NAME);
		verifying.initVerify(derived);
		verifying.update("payload".getBytes());

		assertTrue(verifying.verify(signature),
			"the derived key must verify what the private half signed");
		assertEquals(keyPair.getPublic(), derived);
	}
}
