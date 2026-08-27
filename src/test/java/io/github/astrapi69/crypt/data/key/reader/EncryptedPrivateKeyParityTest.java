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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.AlgorithmParameters;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.data.key.writer.EncryptedPrivateKeyWriter;

/**
 * Parity tests for the {@link EncryptedPrivateKeyWriter} and {@link EncryptedPrivateKeyReader}
 * pair, and regression tests for issue #24.
 * <p>
 * The writer takes every algorithm without complaint. The reader walked a fixed list of four - rsa,
 * diffie-hellman, dsa and ec - and turned running out of guesses into a null, so an edwards or
 * montgomery key was written and then answered with nothing at all.
 */
class EncryptedPrivateKeyParityTest
{

	private static final String PASSWORD = "the-password";

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static PrivateKey newPrivateKey(final String algorithm) throws Exception
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
		return generator.generateKeyPair().getPrivate();
	}

	private static File encrypted(final PrivateKey privateKey, final File tempDir,
		final String name) throws Exception
	{
		File file = new File(tempDir, name + "-encrypted.der");
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(privateKey, file, PASSWORD);
		return file;
	}

	/**
	 * What the writer sealed, the reader opens - as the same key, for every algorithm the writer
	 * accepts. The decrypted content is a pkcs#8 structure, which names its own algorithm, so
	 * nothing has to be guessed at.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "DH" })
	void aSealedKeyIsOpenedAgainWhateverItsAlgorithm(final String algorithm, @TempDir File tempDir)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		File file = encrypted(privateKey, tempDir, algorithm);

		PrivateKey readBack = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(file,
			PASSWORD);

		assertNotNull(readBack, algorithm + " was written by this library and must come back");
		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			algorithm + " must come back as the key that was sealed");
	}

	/**
	 * The optional returning variant answers for the same set, because the two are two ways to the
	 * same reading and must not disagree.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "EC", "Ed25519", "X25519" })
	void theOptionalVariantAgreesWithTheDirectOne(final String algorithm, @TempDir File tempDir)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);
		File file = encrypted(privateKey, tempDir, algorithm);

		assertTrue(EncryptedPrivateKeyReader.getPrivateKey(file, PASSWORD).isPresent(),
			algorithm + " must be present in the optional variant as well");
		assertArrayEquals(privateKey.getEncoded(),
			EncryptedPrivateKeyReader.getPrivateKey(file, PASSWORD).get().getEncoded());
	}

	/**
	 * A wrong password must fail loudly. It used to be indistinguishable from an algorithm the
	 * reader did not know: both came back as null.
	 *
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing fails
	 */
	@Test
	void aWrongPasswordIsRefusedAndNotAnsweredWithNothing(@TempDir File tempDir) throws Exception
	{
		File file = encrypted(newPrivateKey("RSA"), tempDir, "RSA");

		assertThrows(Exception.class, () -> EncryptedPrivateKeyReader
			.readPasswordProtectedPrivateKey(file, "not-the-password"));
		assertFalse(EncryptedPrivateKeyReader.getPrivateKey(file, "not-the-password").isPresent(),
			"the optional variant answers empty for what it cannot open");
	}

	/**
	 * A container the password does open, holding something that is not a key, is its own case: the
	 * decryption worked, so the refusal has to be about the content and must say so rather than
	 * blame the password.
	 *
	 * @throws Exception
	 *             if the container cannot be built
	 */
	@Test
	void whatOpensButIsNoKeyIsRefusedForItsContentAndNotForThePassword() throws Exception
	{
		String pbeAlgorithm = CompoundAlgorithm.PBE_WITH_SHA1_AND_DES_EDE.getAlgorithm();
		byte[] salt = new byte[8];
		AlgorithmParameterSpec parameterSpec = new PBEParameterSpec(salt, 20);
		SecretKey secretKey = SecretKeyFactory.getInstance(pbeAlgorithm)
			.generateSecret(new PBEKeySpec(PASSWORD.toCharArray()));
		Cipher cipher = Cipher.getInstance(pbeAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
		byte[] sealedRubbish = cipher.doFinal("this is not a private key".getBytes());
		AlgorithmParameters parameters = AlgorithmParameters.getInstance(pbeAlgorithm);
		parameters.init(parameterSpec);
		byte[] container = new EncryptedPrivateKeyInfo(parameters, sealedRubbish).getEncoded();

		InvalidKeySpecException refused = assertThrows(InvalidKeySpecException.class,
			() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(container, PASSWORD));

		assertTrue(refused.getMessage().contains("no private key structure"),
			"the message must be about the content, but was: '" + refused.getMessage() + "'");
	}

	/**
	 * A file that holds no encrypted key is refused rather than decoded into rubbish.
	 *
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing fails
	 */
	@Test
	void aFileThatHoldsNoEncryptedKeyIsRefused(@TempDir File tempDir) throws Exception
	{
		File notAKey = new File(tempDir, "not-a-key.der");
		java.nio.file.Files.writeString(notAKey.toPath(), "this file holds no encrypted key");

		assertThrows(Exception.class,
			() -> EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(notAKey, PASSWORD));
	}
}
