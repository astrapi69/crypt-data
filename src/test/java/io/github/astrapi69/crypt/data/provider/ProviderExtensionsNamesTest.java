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
package io.github.astrapi69.crypt.data.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.security.Security;

import org.junit.jupiter.api.Test;

/**
 * Tests that {@link ProviderExtensions#getSupportedProviderNames()} and
 * {@link ProviderExtensions#getSupportedProviderNamesAndVersion()} report every installed provider,
 * in order, with the expected text
 */
class ProviderExtensionsNamesTest
{

	/**
	 * Test method for {@link ProviderExtensions#getSupportedProviderNames()}
	 */
	@Test
	void namesMatchInstalledProvidersInOrder()
	{
		Provider[] providers = Security.getProviders();
		String[] names = ProviderExtensions.getSupportedProviderNames();

		assertTrue(providers.length > 0, "the JDK always installs providers");
		assertEquals(providers.length, names.length);
		for (int i = 0; i < providers.length; i++)
		{
			assertNotNull(names[i], "entry " + i);
			assertEquals(providers[i].getName(), names[i], "entry " + i);
		}
	}

	/**
	 * Test method for {@link ProviderExtensions#getSupportedProviderNamesAndVersion()}
	 */
	@Test
	void namesAndVersionsMatchInstalledProvidersInOrder()
	{
		Provider[] providers = Security.getProviders();
		String[] namesAndVersions = ProviderExtensions.getSupportedProviderNamesAndVersion();

		assertEquals(providers.length, namesAndVersions.length);
		for (int i = 0; i < providers.length; i++)
		{
			assertNotNull(namesAndVersions[i], "entry " + i);
			assertEquals(providers[i].getName() + " " + providers[i].getVersionStr(),
				namesAndVersions[i], "entry " + i);
		}
	}
}
