package io.github.astrapi69.crypto.algorithm;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import org.testng.annotations.Test;

/**
 * Test class for the class {@link CryptoAlgorithm}
 */
public class CryptoAlgorithmTest
{

	/**
	 * Test method for {@link CryptoAlgorithm#newAlgorithm(String)}
	 */
	@Test
	public void testNewAlgorithm()
	{
		String algorithmName = "AES";
		CryptoAlgorithm aes = (CryptoAlgorithm)CryptoAlgorithm.newAlgorithm(algorithmName);
		assertNotNull(aes);
		String name = aes.name();
		assertEquals(algorithmName, name);
	}
}
