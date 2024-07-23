package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.hex.HexExtensions;

/**
 * The unit test class for the class {@link KeyExtensions}
 */
@DisplayName("Unit tests for KeyExtensions")
class KeyExtensionsTest
{

	/**
	 * Helper method to format a {@link Key} into a readable {@link String}.
	 *
	 * @param key
	 *            the {@link Key} to format
	 * @return the formatted {@link String} representation of the {@link Key}
	 */
	private static String formatKey(Key key)
	{
		StringBuffer sb = new StringBuffer();
		String algo = key.getAlgorithm();
		String fmt = key.getFormat();
		byte[] encoded = key.getEncoded();
		sb.append(
			"Key[algorithm=" + algo + ", format=" + fmt + ", bytes=" + encoded.length + "]\n");
		if (fmt.equalsIgnoreCase("RAW"))
		{
			sb.append("Key Material (in hex):: ");
			sb.append(HexExtensions.encodeHex(key.getEncoded()));
		}
		return sb.toString();
	}

	/**
	 * Test method for formatting various keys.
	 */
	@Test
	@DisplayName("Test formatting of various keys")
	void testFormatKey() throws NoSuchAlgorithmException
	{
		KeyGenerator kg = KeyGenerator.getInstance("DES");
		kg.init(56); // 56 is the keysize. Fixed for DES
		SecretKey key = kg.generateKey();
		String formatKey = formatKey(key);
		System.out.println(formatKey);

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		PublicKey pubk = kp.getPublic();
		PrivateKey prvk = kp.getPrivate();
		System.out.println("Generated Public Key:: " + formatKey(pubk));
		System.out.println("Generated Private Key:: " + formatKey(prvk));
	}

	/**
	 * Test method for base64 encoding and decoding.
	 */
	@Test
	@DisplayName("Test base64 encoding and decoding")
	void testBase64EncodingDecoding()
	{
		byte[] originalKey = { 1, 2, 3, 4, 5 };
		String base64Encoded = KeyExtensions.toBase64(originalKey);
		byte[] decodedKey = KeyExtensions.decodeBase64(base64Encoded);
		assertArrayEquals(originalKey, decodedKey);
	}

	/**
	 * Test method for base64 binary encoding and decoding.
	 */
	@Test
	@DisplayName("Test base64 binary encoding and decoding")
	void testBase64BinaryEncodingDecoding()
	{
		byte[] originalKey = { 1, 2, 3, 4, 5 };
		String base64BinaryEncoded = KeyExtensions.toBase64Binary(originalKey);
		byte[] decodedKey = KeyExtensions.decodeBase64(base64BinaryEncoded);
		assertArrayEquals(originalKey, decodedKey);
	}

	/**
	 * Test method for getting algorithm, format, and encoded key.
	 */
	@Test
	@DisplayName("Test getAlgorithm, getFormat, and getEncoded methods")
	void testKeyAttributes() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		PublicKey pubk = kp.getPublic();
		PrivateKey prvk = kp.getPrivate();

		assertEquals("DSA", KeyExtensions.getAlgorithm(pubk));
		assertEquals("X.509", KeyExtensions.getFormat(pubk));
		assertArrayEquals(pubk.getEncoded(), KeyExtensions.getEncoded(pubk));

		assertEquals("DSA", KeyExtensions.getAlgorithm(prvk));
		assertEquals("PKCS#8", KeyExtensions.getFormat(prvk));
		assertArrayEquals(prvk.getEncoded(), KeyExtensions.getEncoded(prvk));
	}
}
