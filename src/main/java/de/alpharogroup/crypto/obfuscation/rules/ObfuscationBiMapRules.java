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
package de.alpharogroup.crypto.obfuscation.rules;

import java.util.Objects;

import com.google.common.collect.BiMap;

/**
 * The class {@link ObfuscationBiMapRules} decorates a {@link BiMap} that defines rules for encrypt
 * and decrypt given strings.
 */
public class ObfuscationBiMapRules<K, V>
{

	public static class ObfuscationBiMapRulesBuilder<K, V>
	{
		private BiMap<K, V> obfuscationRules;

		ObfuscationBiMapRulesBuilder()
		{
		}

		public ObfuscationBiMapRules<K, V> build()
		{
			return new ObfuscationBiMapRules<K, V>(obfuscationRules);
		}

		public ObfuscationBiMapRules.ObfuscationBiMapRulesBuilder<K, V> obfuscationRules(
			BiMap<K, V> obfuscationRules)
		{
			this.obfuscationRules = obfuscationRules;
			return this;
		}

		@Override
		public String toString()
		{
			return "ObfuscationBiMapRules.ObfuscationBiMapRulesBuilder(obfuscationRules="
				+ this.obfuscationRules + ")";
		}
	}

	public static <K, V> ObfuscationBiMapRulesBuilder<K, V> builder()
	{
		return new ObfuscationBiMapRulesBuilder<K, V>();
	}

	/**
	 * The rules for encrypt the string.
	 */
	private final BiMap<K, V> obfuscationRules;

	/**
	 * Instantiates a new {@link ObfuscationBiMapRules}.
	 *
	 * @param obfuscationRules
	 *            the obfuscation rules for obfuscate and disentangle.
	 */
	public ObfuscationBiMapRules(final BiMap<K, V> obfuscationRules)
	{
		Objects.requireNonNull(obfuscationRules);
		this.obfuscationRules = obfuscationRules;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof ObfuscationBiMapRules;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof ObfuscationBiMapRules))
			return false;
		final ObfuscationBiMapRules<?, ?> other = (ObfuscationBiMapRules<?, ?>)o;
		if (!other.canEqual(this))
			return false;
		final Object this$obfuscationRules = this.getObfuscationRules();
		final Object other$obfuscationRules = other.getObfuscationRules();
		if (this$obfuscationRules == null
			? other$obfuscationRules != null
			: !this$obfuscationRules.equals(other$obfuscationRules))
			return false;
		return true;
	}

	public BiMap<K, V> getObfuscationRules()
	{
		return this.obfuscationRules;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $obfuscationRules = this.getObfuscationRules();
		result = result * PRIME + ($obfuscationRules == null ? 43 : $obfuscationRules.hashCode());
		return result;
	}

	@Override
	public String toString()
	{
		return "ObfuscationBiMapRules(obfuscationRules=" + this.getObfuscationRules() + ")";
	}
}
