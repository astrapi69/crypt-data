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
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for {@link Pkcs11Factory} against a locally installed SoftHSM2 module.
 * <p>
 * The tests that need a token skip themselves unless the SoftHSM2 library is installed and the
 * current user has at least one initialized token in the default SoftHSM2 token directory
 * ({@code ~/.config/softhsm2/tokens}, the directory SoftHSM2 uses when no {@code SOFTHSM2_CONF}
 * environment variable is set). The user PIN of that token is expected to be {@value #PIN}. The
 * tests never create token objects: all generated keys are session objects that vanish when the
 * provider is released.
 */
class Pkcs11FactorySoftHsmTest
{

	private static final String PIN = "123456";

	private static final List<String> LIBRARY_CANDIDATES = List.of(
		"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so");

	/**
	 * One named curve the token is asked to generate a key pair for
	 *
	 * @param curveName
	 *            the curve name
	 * @param signatureAlgorithm
	 *            the signature algorithm to use with keys on that curve
	 */
	record CurveCase(String curveName, String signatureAlgorithm) {
	}

	static Stream<CurveCase> curveCases()
	{
		return Stream.of(new CurveCase("secp256r1", "SHA256withECDSA"),
			new CurveCase("secp384r1", "SHA384withECDSA"));
	}

	private static File findSoftHsmLibrary()
	{
		return LIBRARY_CANDIDATES.stream().map(File::new).filter(File::isFile).findFirst()
			.orElse(null);
	}

	private static boolean hasInitializedToken()
	{
		File tokenDir = new File(System.getProperty("user.home"), ".config/softhsm2/tokens");
		File[] tokens = tokenDir.listFiles(File::isDirectory);
		return tokens != null && tokens.length > 0;
	}

	private static String writeConfig(final Path directory, final File library) throws IOException
	{
		Path config = directory.resolve("softhsm-pkcs11.cfg");
		String content = "name = SoftHsmTest\nlibrary = " + library.getAbsolutePath()
			+ "\nslotListIndex = 0\n";
		Files.writeString(config, content, StandardCharsets.UTF_8);
		return config.toString();
	}

	private static String assumeSoftHsmConfig(final Path directory) throws IOException
	{
		File library = findSoftHsmLibrary();
		assumeTrue(library != null, "SoftHSM2 library not installed - skipping");
		assumeTrue(hasInitializedToken(),
			"no initialized SoftHSM2 token in ~/.config/softhsm2/tokens - skipping");
		return writeConfig(directory, library);
	}

	/**
	 * Test method for {@link Pkcs11Factory#newProvider(String)}: the returned provider is a
	 * configured SunPKCS11 provider that is not registered globally
	 *
	 * @param directory
	 *            the temporary directory for the config file
	 * @throws Exception
	 *             if the provider cannot be configured
	 */
	@Test
	void newProviderIsConfiguredButNotRegistered(@TempDir final Path directory) throws Exception
	{
		String configPath = assumeSoftHsmConfig(directory);

		Provider provider = Pkcs11Factory.newProvider(configPath);

		assertNotNull(provider);
		assertEquals("SunPKCS11-SoftHsmTest", provider.getName());
		assertTrue(provider.isConfigured());
		assertNotNull(provider.getService("KeyStore", "PKCS11"));
		assertFalse(Arrays.asList(Security.getProviders()).contains(provider),
			"the factory must not register the provider globally");
	}

	/**
	 * Test method for {@link Pkcs11Factory#newProvider(String)} with a config file that does not
	 * exist: SunPKCS11 reports the unreadable config as an {@link InvalidParameterException}
	 *
	 * @param directory
	 *            the temporary directory
	 */
	@Test
	void newProviderWithMissingConfigFails(@TempDir final Path directory)
	{
		String missing = directory.resolve("does-not-exist.cfg").toString();

		InvalidParameterException actual = assertThrows(InvalidParameterException.class,
			() -> Pkcs11Factory.newProvider(missing));
		assertTrue(actual.getMessage().contains("SunPKCS11"));
	}

	/**
	 * Test method for {@link Pkcs11Factory#newProvider(String)} when the JDK does not offer the
	 * SunPKCS11 provider: it is temporarily removed from the provider list for this test
	 *
	 * @param directory
	 *            the temporary directory
	 * @throws Exception
	 *             if the config file cannot be written
	 */
	@Test
	void newProviderWithoutSunPkcs11Fails(@TempDir final Path directory) throws Exception
	{
		Provider sunPkcs11 = Security.getProvider("SunPKCS11");
		assumeTrue(sunPkcs11 != null, "SunPKCS11 not present in this JDK - skipping");
		int position = Arrays.asList(Security.getProviders()).indexOf(sunPkcs11) + 1;
		String configPath = writeConfig(directory, new File("/nonexistent/libpkcs11.so"));

		Security.removeProvider(sunPkcs11.getName());
		try
		{
			IllegalStateException actual = assertThrows(IllegalStateException.class,
				() -> Pkcs11Factory.newProvider(configPath));
			assertTrue(actual.getMessage().contains("SunPKCS11"));
		}
		finally
		{
			Security.insertProviderAt(sunPkcs11, position);
		}
		assertNotNull(Security.getProvider("SunPKCS11"), "provider must be restored");
	}

	/**
	 * Test method for {@link Pkcs11Factory#newKeyStore(Provider, char[])}: the token keystore is
	 * opened with the user PIN and exposes the PKCS11 type
	 *
	 * @param directory
	 *            the temporary directory for the config file
	 * @throws Exception
	 *             if the keystore cannot be opened
	 */
	@Test
	void newKeyStoreOpensToken(@TempDir final Path directory) throws Exception
	{
		String configPath = assumeSoftHsmConfig(directory);
		Provider provider = Pkcs11Factory.newProvider(configPath);

		KeyStore keyStore = Pkcs11Factory.newKeyStore(provider, PIN.toCharArray());

		assertNotNull(keyStore);
		assertEquals("PKCS11", keyStore.getType());
		assertEquals(provider, keyStore.getProvider());
		assertNotNull(keyStore.aliases(), "a loaded keystore must enumerate its aliases");
	}

	/**
	 * Test method proving that a key pair generated on the token through the configured provider
	 * signs and verifies, and that the verification is sensitive to the data
	 *
	 * @param testCase
	 *            the curve to use
	 * @param directory
	 *            the temporary directory for the config file
	 * @throws Exception
	 *             if signing fails
	 */
	@ParameterizedTest
	@MethodSource("curveCases")
	void keyPairFromTokenSignsAndVerifies(final CurveCase testCase, @TempDir final Path directory)
		throws Exception
	{
		String configPath = assumeSoftHsmConfig(directory);
		Provider provider = Pkcs11Factory.newProvider(configPath);
		// log in so that key generation is permitted on the token
		Pkcs11Factory.newKeyStore(provider, PIN.toCharArray());

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
		keyPairGenerator.initialize(new ECGenParameterSpec(testCase.curveName()));
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		byte[] data = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

		Signature signer = Signature.getInstance(testCase.signatureAlgorithm(), provider);
		signer.initSign(keyPair.getPrivate());
		signer.update(data);
		byte[] signature = signer.sign();

		Signature verifier = Signature.getInstance(testCase.signatureAlgorithm(), provider);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(data);
		assertTrue(verifier.verify(signature), testCase.toString());

		verifier.initVerify(keyPair.getPublic());
		verifier.update("the quick brown cat".getBytes(StandardCharsets.UTF_8));
		assertFalse(verifier.verify(signature), testCase.toString());
	}
}
