package io.github.astrapi69.crypt.data.processor.certificate;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateVerifierTest
{

	@BeforeEach
	public void setUp()
	{
		// Add BouncyCastle as a security provider for the tests
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void getSupportedSignatureAlgorithms() throws NoSuchAlgorithmException, NoSuchProviderException,
		InvocationTargetException, NoSuchMethodException, IllegalAccessException
	{
		Map<String, Set<String>> supportedSignatureAlgorithms = CertificateVerifier
			.getSupportedSignatureAlgorithms("KeyPairGenerator", KeyPairGenerator.class,
				KeyPairGenerator::initialize, 255, 2048, 1);

		// Assert that the result is not null
		assertNotNull(supportedSignatureAlgorithms);
	}
}