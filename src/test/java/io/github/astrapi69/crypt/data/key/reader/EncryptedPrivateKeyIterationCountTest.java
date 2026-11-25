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
package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * How {@link EncryptedPrivateKeyReader} reads the iteration count of a password protected key file
 * in DER form: the file names its password-based encryption scheme and the count, and the reader
 * derives the key only when the count lies within 1 to 10000000. The files are written here at run
 * time; their encrypted part is random bytes, so a derived key ends in the report that the password
 * does not open the key
 */
class EncryptedPrivateKeyIterationCountTest
{
	private static final SecureRandom RANDOM = new SecureRandom();

	/** Well below the time a derivation of more than the bound would take on any scheme */
	private static final Duration REFUSED_AT_ONCE = Duration.ofSeconds(5);

	private static String password;

	@BeforeAll
	static void registerBouncyCastleAndMakeAPassword()
	{
		Security.addProvider(new BouncyCastleProvider());
		byte[] bytes = new byte[12];
		RANDOM.nextBytes(bytes);
		password = HexFormat.of().formatHex(bytes);
	}

	@Test
	@DisplayName("a key file that names 10000001 iterations of PKCS#12 triple DES is refused before the key is derived")
	void aKeyFileNamingMoreThanTenMillionIterations_isRefusedBeforeTheKeyIsDerived()
	{
		byte[] keyFile = keyFile(Scheme.PKCS12_TRIPLE_DES, 10_000_001);

		InvalidAlgorithmParameterException refused = assertTimeoutPreemptively(REFUSED_AT_ONCE,
			() -> assertThrows(InvalidAlgorithmParameterException.class,
				() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(keyFile,
					password)));

		assertEquals("The key file asks for 10000001 iterations of its password-based encryption;"
			+ " 1 to 10000000 are allowed", refused.getMessage());
	}

	static Stream<Arguments> schemesAndCountsOutsideTheBound()
	{
		return Stream.of(Scheme.values()).flatMap(scheme -> Stream.of(Arguments.of(scheme, 0),
			Arguments.of(scheme, 10_000_001), Arguments.of(scheme, Integer.MAX_VALUE)));
	}

	@ParameterizedTest(name = "{0} with {1} iterations is refused before the key is derived")
	@MethodSource("schemesAndCountsOutsideTheBound")
	void aCountOutsideTheBound_isRefusedBeforeTheKeyIsDerived(final Scheme scheme,
		final int iterationCount)
	{
		byte[] keyFile = keyFile(scheme, iterationCount);

		InvalidAlgorithmParameterException refused = assertTimeoutPreemptively(REFUSED_AT_ONCE,
			() -> assertThrows(InvalidAlgorithmParameterException.class,
				() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(keyFile,
					password)));

		assertTrue(refused.getMessage().startsWith("The key file asks for " + iterationCount + " "),
			refused.getMessage());
	}

	/**
	 * Every scheme but Bouncy Castle's PBES1 with SHA-1 and DES: its cipher refuses the parameters
	 * the JDK reads from the file at init ("Need a PBEParameter spec with a PBE key"), so this
	 * reader never derived a key for it; the bound refuses it all the same
	 */
	static Stream<Arguments> schemesWithACountWithinTheBound()
	{
		return Stream.of(Scheme.values()).filter(scheme -> scheme != Scheme.PBES1_SHA1_DES)
			.map(scheme -> Arguments.of(scheme, 2048));
	}

	@ParameterizedTest(name = "{0} with {1} iterations is derived and opened with the password")
	@MethodSource("schemesWithACountWithinTheBound")
	void aCountWithinTheBound_isDerived(final Scheme scheme, final int iterationCount)
	{
		byte[] keyFile = keyFile(scheme, iterationCount);

		InvalidKeySpecException derived = assertThrows(InvalidKeySpecException.class,
			() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(keyFile, password));

		assertDerived(derived);
	}

	@Test
	@DisplayName("a key file that names exactly 10000000 iterations is derived")
	void aKeyFileNamingTheBound_isDerived()
	{
		byte[] keyFile = keyFile(Scheme.PBES1_MD5_DES, 10_000_000);

		InvalidKeySpecException derived = assertThrows(InvalidKeySpecException.class,
			() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(keyFile, password));

		assertDerived(derived);
	}

	@Test
	@DisplayName("a key file whose scheme names no count this reader knows is refused")
	void aKeyFileWithAnUnknownScheme_isRefused()
	{
		byte[] keyFile = encode(new ASN1ObjectIdentifier("1.2.3.4"), DERNull.INSTANCE);

		InvalidAlgorithmParameterException refused = assertThrows(
			InvalidAlgorithmParameterException.class,
			() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(keyFile, password));

		assertEquals("The key file is encrypted with 1.2.3.4, a scheme whose iteration count this"
			+ " reader does not read", refused.getMessage());
	}

	/**
	 * The reader's own refusal of a PBES2 key derivation it does not know. Through
	 * readPasswordProtectedPrivateKey such a file is refused earlier, by the JDK while it reads the
	 * file (EncryptedPrivateKeyInfo's constructor parses the PBES2 parameters and knows only
	 * PBKDF2), so the refusal is held here directly
	 */
	@Test
	@DisplayName("a PBES2 key file whose key derivation is not PBKDF2 is refused")
	void aPbes2KeyFileWithAnotherKeyDerivation_isRefused()
	{
		ASN1ObjectIdentifier scrypt = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.4.11");
		byte[] keyFile = encode(PKCSObjectIdentifiers.id_PBES2,
			new PBES2Parameters(
				new KeyDerivationFunc(scrypt,
					new DERSequence(new ASN1Encodable[] { new DEROctetString(random(16)),
							new ASN1Integer(16384), new ASN1Integer(8), new ASN1Integer(1) })),
				new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC,
					new DEROctetString(random(16)))));

		InvalidAlgorithmParameterException refused = assertThrows(
			InvalidAlgorithmParameterException.class,
			() -> EncryptedPrivateKeyReader.iterationCountOf(keyFile));

		assertEquals("The key file derives its key with 1.3.6.1.4.1.11591.4.11, whose iteration"
			+ " count this reader does not read", refused.getMessage());
	}

	/**
	 * The reader's own refusal of parameters it cannot read. Through
	 * readPasswordProtectedPrivateKey such a file is refused earlier, by the JDK while it reads the
	 * file, so the refusal is held here directly
	 */
	@Test
	@DisplayName("a PKCS#12 key file whose parameters are no PKCS#12 parameters is refused")
	void aKeyFileWithUnreadableParameters_isRefused()
	{
		byte[] keyFile = encode(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
			DERNull.INSTANCE);

		InvalidAlgorithmParameterException refused = assertThrows(
			InvalidAlgorithmParameterException.class,
			() -> EncryptedPrivateKeyReader.iterationCountOf(keyFile));

		assertTrue(
			refused.getMessage().startsWith(
				"The parameters of the key file's password-based encryption cannot be read: "),
			refused.getMessage());
	}

	/**
	 * Holds that the key was derived and then refused as no key: random encrypted bytes mostly end
	 * in a padding the cipher refuses, and about once in 256 decryptions with an 8-byte block
	 * cipher in a padding it takes, after which what was decrypted is no private key structure
	 */
	private static void assertDerived(final InvalidKeySpecException derived)
	{
		String message = derived.getMessage();
		assertTrue(message.startsWith("The password does not open this key")
			|| message.startsWith("What was decrypted is no private key structure"), message);
	}

	/**
	 * The password-based encryption schemes a key file can name: served by the JDK or only by
	 * Bouncy Castle
	 */
	enum Scheme
	{
		/** PKCS#12, SHA-1 and three-key triple DES, served by SunJCE */
		PKCS12_TRIPLE_DES,
		/** PKCS#12, SHA-1 and two-key triple DES, served by Bouncy Castle only */
		PKCS12_TWO_KEY_TRIPLE_DES,
		/** PBES1, MD5 and DES, served by SunJCE */
		PBES1_MD5_DES,
		/** PBES1, SHA-1 and DES, served by Bouncy Castle only */
		PBES1_SHA1_DES,
		/** PBES2 with PBKDF2 (HMAC-SHA256) and AES-256, served by SunJCE */
		PBES2_PBKDF2_AES
	}

	/**
	 * A DER EncryptedPrivateKeyInfo with the given scheme and count and random encrypted bytes
	 */
	static byte[] keyFile(final Scheme scheme, final int iterationCount)
	{
		byte[] salt = random(16);
		return switch (scheme)
		{
			case PKCS12_TRIPLE_DES -> encode(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
				new PKCS12PBEParams(salt, iterationCount));
			case PKCS12_TWO_KEY_TRIPLE_DES -> encode(
				PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC,
				new PKCS12PBEParams(salt, iterationCount));
			case PBES1_MD5_DES -> encode(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC,
				new PBEParameter(random(8), iterationCount));
			case PBES1_SHA1_DES -> encode(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC,
				new PBEParameter(random(8), iterationCount));
			case PBES2_PBKDF2_AES -> encode(PKCSObjectIdentifiers.id_PBES2,
				new PBES2Parameters(
					new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
						new PBKDF2Params(salt, iterationCount,
							new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256,
								DERNull.INSTANCE))),
					new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC,
						new DEROctetString(random(16)))));
		};
	}

	private static byte[] encode(final ASN1ObjectIdentifier schemeId,
		final ASN1Encodable parameters)
	{
		try
		{
			return new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(schemeId, parameters),
				random(1232)).getEncoded("DER");
		}
		catch (IOException encodingFailed)
		{
			throw new IllegalStateException("the key file could not be encoded", encodingFailed);
		}
	}

	private static byte[] random(final int length)
	{
		byte[] bytes = new byte[length];
		RANDOM.nextBytes(bytes);
		return bytes;
	}
}
