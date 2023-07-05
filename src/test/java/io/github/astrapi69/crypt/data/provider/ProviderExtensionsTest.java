package io.github.astrapi69.crypt.data.provider;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Provider;
import java.security.cert.Certificate;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.key.CertificateExtensions;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The unit test class for the class {@link ProviderExtensions}
 */
class ProviderExtensionsTest
{

	/**
	 * Test method for {@link ProviderExtensions#getSupportedProviders()}
	 */
	@Test
	void getSupportedProviders()
	{
		Provider[] supportedProviders;

		supportedProviders = ProviderExtensions.getSupportedProviders();
		assertNotNull(supportedProviders);
	}

	/**
	 * Test method for {@link ProviderExtensions#getSupportedProviderNames()}
	 */
	@Test
	void getSupportedProviderNames()
	{
		String[] supportedProviderNames;

		supportedProviderNames = ProviderExtensions.getSupportedProviderNames();
		assertNotNull(supportedProviderNames);
	}

	/**
	 * Test method for {@link ProviderExtensions#getSupportedProviderNamesAndVersion()}
	 */
	@Test
	void getSupportedProviderNamesAndVersion()
	{
		String[] supportedProviderNamesAndVersion;

		supportedProviderNamesAndVersion = ProviderExtensions.getSupportedProviderNamesAndVersion();
		assertNotNull(supportedProviderNamesAndVersion);
	}
}