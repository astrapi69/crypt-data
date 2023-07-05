package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.hex.HexExtensions;

class KeyExtensionsTest
{

	/**
	 * Test method for format key
	 */
	@Test
	public void testFormatKey() throws NoSuchAlgorithmException
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

	public static String formatKey(Key key)
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
}