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

import java.security.Provider;
import java.security.Security;

/**
 * The extension class {@link ProviderExtensions} provides algorithm for Provider information
 */
public final class ProviderExtensions
{

	/**
	 * Gets an array with all the installed providers
	 * 
	 * @return an array with all the installed providers
	 */
	public static Provider[] getSupportedProviders()
	{
		return Security.getProviders();
	}


	/**
	 * Gets an array with all the installed provider names
	 * 
	 * @return an array with all the installed provider names
	 */
	public static String[] getSupportedProviderNames()
	{
		Provider[] providers = getSupportedProviders();
		String[] providerNames = new String[providers.length];
		for (int i = 0; i < providers.length; i++)
		{
			providerNames[i] = providers[i].getName();
		}
		return providerNames;
	}

	/**
	 * Gets an array with all the installed provider names with the corresponding versions
	 * 
	 * @return array with all the installed provider names with the corresponding versions
	 */
	public static String[] getSupportedProviderNamesAndVersion()
	{
		Provider[] providers = getSupportedProviders();
		String[] providerNames = new String[providers.length];
		for (int i = 0; i < providers.length; i++)
		{
			String name = providers[i].getName();
			double version = providers[i].getVersion();
			providerNames[i] = name + " " + version;
		}
		return providerNames;
	}
}
