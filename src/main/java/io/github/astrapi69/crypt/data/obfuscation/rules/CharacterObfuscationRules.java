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
package io.github.astrapi69.crypt.data.obfuscation.rules;

import com.google.common.collect.BiMap;

/**
 * The class {@link CharacterObfuscationRules} can define a simple rule for encrypt and decrypt a
 * key.
 */
public class CharacterObfuscationRules extends ObfuscationBiMapRules<Character, Character>
{

	/**
	 * Instantiates a new {@link CharacterObfuscationRules}.
	 *
	 * @param obfuscationRules
	 *            the obfuscation rules
	 */
	public CharacterObfuscationRules(BiMap<Character, Character> obfuscationRules)
	{
		super(obfuscationRules);
	}

	/**
	 * Rules builder character obfuscation rules builder.
	 *
	 * @return the character obfuscation rules builder
	 */
	public static CharacterObfuscationRulesBuilder rulesBuilder()
	{
		return new CharacterObfuscationRulesBuilder();
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CharacterObfuscationRules))
			return false;
		final CharacterObfuscationRules other = (CharacterObfuscationRules)o;
		return super.equals(o);
	}

	@Override
	public int hashCode()
	{
		int result = super.hashCode();
		return result;
	}

	@Override
	public String toString()
	{
		return "CharacterObfuscationRules(super=" + super.toString() + ")";
	}

	/**
	 * The type Character obfuscation rules builder.
	 */
	public static class CharacterObfuscationRulesBuilder
	{
		private BiMap<Character, Character> obfuscationRules;

		/**
		 * Instantiates a new Character obfuscation rules builder.
		 */
		CharacterObfuscationRulesBuilder()
		{
		}

		/**
		 * Build character obfuscation rules.
		 *
		 * @return the character obfuscation rules
		 */
		public CharacterObfuscationRules build()
		{
			return new CharacterObfuscationRules(obfuscationRules);
		}

		/**
		 * Obfuscation rules character obfuscation rules . character obfuscation rules builder.
		 *
		 * @param obfuscationRules
		 *            the obfuscation rules
		 * @return the character obfuscation rules . character obfuscation rules builder
		 */
		public CharacterObfuscationRules.CharacterObfuscationRulesBuilder obfuscationRules(
			BiMap<Character, Character> obfuscationRules)
		{
			this.obfuscationRules = obfuscationRules;
			return this;
		}

		@Override
		public String toString()
		{
			return "CharacterObfuscationRules.CharacterObfuscationRulesBuilder(obfuscationRules="
				+ this.obfuscationRules + ")";
		}
	}
}
