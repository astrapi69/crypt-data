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
package de.alpharogroup.crypto.obfuscation.rule;

import java.io.Serializable;
import java.util.Objects;

public class ObfuscationRule<C, RW> implements Serializable
{
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	/** The character. */
	private C character;
	/** The character(s) that will be replaced with. */
	private RW replaceWith;

	public ObfuscationRule()
	{
	}

	public ObfuscationRule(C character, RW replaceWith)
	{
		Objects.requireNonNull(character);
		Objects.requireNonNull(replaceWith);
		this.character = character;
		this.replaceWith = replaceWith;
	}

	public static <C, RW> ObfuscationRuleBuilder<C, RW> builder()
	{
		return new ObfuscationRuleBuilder<C, RW>();
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof ObfuscationRule;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof ObfuscationRule))
			return false;
		final ObfuscationRule<?, ?> other = (ObfuscationRule<?, ?>)o;
		if (!other.canEqual(this))
			return false;
		final Object this$character = this.getCharacter();
		final Object other$character = other.getCharacter();
		if (this$character == null
			? other$character != null
			: !this$character.equals(other$character))
			return false;
		final Object this$replaceWith = this.getReplaceWith();
		final Object other$replaceWith = other.getReplaceWith();
		if (this$replaceWith == null
			? other$replaceWith != null
			: !this$replaceWith.equals(other$replaceWith))
			return false;
		return true;
	}

	public C getCharacter()
	{
		return this.character;
	}

	public void setCharacter(C character)
	{
		Objects.requireNonNull(character);
		this.character = character;
	}

	public RW getReplaceWith()
	{
		return this.replaceWith;
	}

	public void setReplaceWith(RW replaceWith)
	{
		Objects.requireNonNull(replaceWith);
		this.replaceWith = replaceWith;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $character = this.getCharacter();
		result = result * PRIME + ($character == null ? 43 : $character.hashCode());
		final Object $replaceWith = this.getReplaceWith();
		result = result * PRIME + ($replaceWith == null ? 43 : $replaceWith.hashCode());
		return result;
	}

	public ObfuscationRuleBuilder<C, RW> toBuilder()
	{
		return new ObfuscationRuleBuilder<C, RW>().character(this.character)
			.replaceWith(this.replaceWith);
	}

	@Override
	public String toString()
	{
		return "ObfuscationRule(character=" + this.getCharacter() + ", replaceWith="
			+ this.getReplaceWith() + ")";
	}

	public static class ObfuscationRuleBuilder<C, RW>
	{
		private C character;
		private RW replaceWith;

		ObfuscationRuleBuilder()
		{
		}

		public ObfuscationRule<C, RW> build()
		{
			return new ObfuscationRule<C, RW>(character, replaceWith);
		}

		public ObfuscationRule.ObfuscationRuleBuilder<C, RW> character(C character)
		{
			Objects.requireNonNull(character);
			this.character = character;
			return this;
		}

		public ObfuscationRule.ObfuscationRuleBuilder<C, RW> replaceWith(RW replaceWith)
		{
			Objects.requireNonNull(replaceWith);
			this.replaceWith = replaceWith;
			return this;
		}

		@Override
		public String toString()
		{
			return "ObfuscationRule.ObfuscationRuleBuilder(character=" + this.character
				+ ", replaceWith=" + this.replaceWith + ")";
		}
	}
}
