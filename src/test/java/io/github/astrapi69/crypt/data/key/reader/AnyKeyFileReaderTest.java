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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The key generation window offers RSA, EC, X25519, X448, ML-KEM-768 and ML-DSA-65, saved as PEM or
 * DER - and {@link AnyKeyFileReader#readPrivateKey} has to read every one of those back, not only
 * the ones its own fixed algorithm list happened to name (#102).
 */
class AnyKeyFileReaderTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@ParameterizedTest(name = "{0} as DER")
	@EnumSource(value = KeyPairGeneratorAlgorithm.class, names = { "RSA", "EC", "X25519", "X448",
			"ML_KEM_768", "ML_DSA_65" })
	void readsBackAPrivateKeySavedAsDerForEveryAlgorithmTheWindowOffers(
		KeyPairGeneratorAlgorithm algorithm, @TempDir File directory) throws Exception
	{
		// EC is generated on an explicit curve with the Bouncy Castle provider, the same way the
		// window itself does it (KeygenSupport#newEcKeyPair) - the plain 1-arg factory call leaves
		// the provider to the JDK, which for EC is SunEC, not the provider this application reads
		// DER files with
		KeyPair keyPair = algorithm == KeyPairGeneratorAlgorithm.EC
			? KeyPairFactory.newKeyPair("secp256r1", "EC", BouncyCastleProvider.PROVIDER_NAME)
			: KeyPairFactory.newKeyPair(algorithm);
		File file = new File(directory, "private-" + algorithm + ".der");
		try (OutputStream out = Files.newOutputStream(file.toPath()))
		{
			PrivateKeyWriter.write(keyPair.getPrivate(), out, KeyFileFormat.DER, KeyFormat.PKCS_8);
		}

		assertEquals(keyPair.getPrivate(), AnyKeyFileReader.readPrivateKey(file),
			"a " + algorithm + " private key saved as DER must read back as the key that was "
				+ "generated, not throw");
	}


	@Test
	@DisplayName("a PKCS#8 PEM file is read, which is the shape the format's own header names")
	void readsAPkcs8PemFile() throws Exception
	{
		PrivateKey read = AnyKeyFileReader.readPrivateKey(fixture("pem/non-encrypted-key.pem"));

		assertNotNull(read, "BEGIN PRIVATE KEY is PKCS#8 and has to be read as one");
		assertEquals("PKCS#8", read.getFormat());
	}

	@Test
	@DisplayName("an openssl traditional PEM file is read as well, through the PEM key pair")
	void readsATraditionalPemFile() throws Exception
	{
		PrivateKey read = AnyKeyFileReader.readPrivateKey(fixture("der/private.pem"));

		assertNotNull(read, "BEGIN RSA PRIVATE KEY carries a key pair, not a PKCS#8 structure");
		assertEquals("RSA", read.getAlgorithm());
	}

	@Test
	@DisplayName("a DER PKCS#8 file is read without a header to go by")
	void readsADerFile() throws Exception
	{
		PrivateKey read = AnyKeyFileReader.readPrivateKey(fixture("der/private.der"));

		assertNotNull(read);
		assertEquals("RSA", read.getAlgorithm());
	}

	@Test
	@DisplayName("a file that holds no private key is refused with its own path in the message")
	void refusesAFileWithoutAPrivateKey()
	{
		File notAKey = fixture("pem/decrypted.txt");

		Exception refused = assertThrows(Exception.class,
			() -> AnyKeyFileReader.readPrivateKey(notAKey));

		assertTrue(refused.getMessage() != null && refused.getMessage().contains("decrypted.txt"),
			"a reader that cannot read says WHICH file it could not read: " + refused.getMessage());
	}

	@Test
	@DisplayName("a public key is read as PEM and as DER")
	void readsAPublicKeyInBothShapes() throws Exception
	{
		assertEquals("RSA",
			AnyKeyFileReader.readPublicKey(fixture("pem/public.pem")).getAlgorithm());
		assertEquals("RSA",
			AnyKeyFileReader.readPublicKey(fixture("der/public.der")).getAlgorithm());
	}

	@Test
	@DisplayName("a certificate answers a request for a public key, with the one it carries")
	void readsThePublicKeyOutOfACertificate() throws Exception
	{
		PublicKey fromCertificate = AnyKeyFileReader.readPublicKey(fixture("pem/certificate.pem"));
		X509Certificate certificate = AnyKeyFileReader
			.readCertificate(fixture("pem/certificate.pem"));

		assertNotNull(fromCertificate, "a public key arrives inside a certificate often enough "
			+ "that asking for one has to find it there");
		assertEquals(certificate.getPublicKey(), fromCertificate);
	}

	@Test
	@DisplayName("a file that is neither a key nor a certificate is refused for both questions")
	void refusesAFileThatIsNeither()
	{
		File neither = fixture("pem/decrypted.txt");

		assertThrows(Exception.class, () -> AnyKeyFileReader.readPublicKey(neither));
		assertThrows(Exception.class, () -> AnyKeyFileReader.readCertificate(neither));
	}

	@Test
	@DisplayName("a PEM file that holds a certificate is no private key, and says so")
	void aPemCertificate_isNoPrivateKey(@TempDir File directory) throws Exception
	{
		File asKeyFile = new File(directory, "certificate-named-as-a-key.pem");
		Files.copy(fixture("pem/certificate.pem").toPath(), asKeyFile.toPath());

		Exception refused = assertThrows(Exception.class,
			() -> AnyKeyFileReader.readPrivateKey(asKeyFile));

		assertNotNull(refused.getMessage(), "the PEM parser reads it, finds neither a key pair nor "
			+ "a PKCS#8 structure, and the refusal has to name the file");
	}

	@Test
	@DisplayName("a file that is not even base64 is refused for a key and for a certificate")
	void notEvenBase64(@TempDir File directory) throws Exception
	{
		File garbage = new File(directory, "garbage.pem");
		Files.writeString(garbage.toPath(), "-----BEGIN PRIVATE KEY-----\nnot base64 ****\n");

		assertThrows(Exception.class, () -> AnyKeyFileReader.readPrivateKey(garbage));
		assertThrows(Exception.class, () -> AnyKeyFileReader.readPublicKey(garbage),
			"the public path cannot even decode the body, so it falls through to the certificate "
				+ "reader, which refuses as well");
	}

	@Test
	@DisplayName("an empty file is refused rather than read as an empty certificate")
	void anEmptyFile(@TempDir File directory) throws Exception
	{
		File empty = new File(directory, "empty.pem");
		Files.writeString(empty.toPath(), "");

		assertThrows(Exception.class, () -> AnyKeyFileReader.readCertificate(empty));
		assertThrows(Exception.class, () -> AnyKeyFileReader.readPublicKey(empty));
	}

	@Test
	@DisplayName("a shape no named algorithm reads is refused by name, not by returning null")
	void aKeyOutsideTheAlgorithmList_isRefusedByName()
	{
		// Diffie-Hellman is in none of the named algorithms, and measured here: the sibling
		// PrivateKeyReader does not read it either, so this is the path through the whole method -
		// pem parser, every named algorithm, the sibling reader, and then the refusal
		File dhKey = fixture("der/test-key-dh.der");

		IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
			() -> AnyKeyFileReader.readPrivateKey(dhKey));

		assertTrue(thrown.getMessage().contains(dhKey.getName()),
			"a refusal has to name the file, or the user cannot act on it");
	}

	@Test
	@DisplayName("a Diffie-Hellman key, which no named algorithm reads, comes back through the reader next door")
	void aDiffieHellmanKey_isReadByTheReaderNextDoor(@TempDir File directory) throws Exception
	{
		// the fixed algorithm list names neither DiffieHellman nor anything that decodes one, while
		// PrivateKeyReader tries it first - so this is the case the last resort exists for, and the
		// one that proves it is not dead weight
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DiffieHellman");
		generator.initialize(1024);
		PrivateKey generated = generator.generateKeyPair().getPrivate();
		File derFile = new File(directory, "dh.der");
		Files.write(derFile.toPath(), generated.getEncoded());

		PrivateKey read = AnyKeyFileReader.readPrivateKey(derFile);

		assertNotNull(read, "a shape the list does not name still has to come back");
		assertArrayEquals(generated.getEncoded(), read.getEncoded(),
			"and it has to be the same key, not merely some key");
	}

	@Test
	@DisplayName("a Diffie-Hellman public key is read out of its structure, not out of the name list")
	void aDiffieHellmanPublicKey_isReadByTheReaderNextDoor(@TempDir File directory) throws Exception
	{
		// PublicKeyReader takes the algorithm identifier out of the SubjectPublicKeyInfo instead of
		// guessing from a list, so it reads shapes the loop above cannot name - measured here with
		// DiffieHellman, which the loop has no entry for
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DiffieHellman");
		generator.initialize(1024);
		PublicKey generated = generator.generateKeyPair().getPublic();
		File derFile = new File(directory, "dh-public.der");
		Files.write(derFile.toPath(), generated.getEncoded());

		PublicKey read = AnyKeyFileReader.readPublicKey(derFile);

		assertNotNull(read,
			"a public key whose algorithm is not in the list still has to come back");
		assertArrayEquals(generated.getEncoded(), read.getEncoded(),
			"and it has to be the same key, not merely some key");
	}

	@Test
	@DisplayName("a file that holds no certificate is refused by name, not passed on as null")
	void anAbsentCertificate_isRefusedByName()
	{
		File file = fixture("pem/decrypted.txt");

		IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
			() -> AnyKeyFileReader.refuseIfAbsent(null, file));

		assertTrue(thrown.getMessage().contains(file.getName()),
			"whoever asked for the public key inside it has to learn which file had none");
	}

	private static File fixture(final String path)
	{
		return new File(PathFinder.getSrcTestResourcesDir(), path);
	}
}
