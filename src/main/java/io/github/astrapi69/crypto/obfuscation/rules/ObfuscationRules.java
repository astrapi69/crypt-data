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
package io.github.astrapi69.crypto.obfuscation.rules;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import io.github.astrapi69.crypto.obfuscation.rule.ObfuscationRule;

/**
 * The class {@link ObfuscationRules} holds a list of obfuscation rules that will be processed with
 * an Obfusactor implementation.
 */
public class ObfuscationRules<C, RW>
{

	/** The obfuscation rules. */
	private List<ObfuscationRule<C, RW>> rules;

	public ObfuscationRules()
	{
	}

	public ObfuscationRules(List<ObfuscationRule<C, RW>> rules)
	{
		this.rules = rules;
	}

	public static <C, RW> ObfuscationRulesBuilder<C, RW> builder()
	{
		return new ObfuscationRulesBuilder<C, RW>();
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof ObfuscationRules;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof ObfuscationRules))
			return false;
		final ObfuscationRules<?, ?> other = (ObfuscationRules<?, ?>)o;
		if (!other.canEqual(this))
			return false;
		final Object this$rules = this.getRules();
		final Object other$rules = other.getRules();
		return this$rules == null ? other$rules == null : this$rules.equals(other$rules);
	}

	public List<ObfuscationRule<C, RW>> getRules()
	{
		return this.rules;
	}

	public void setRules(List<ObfuscationRule<C, RW>> rules)
	{
		this.rules = rules;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $rules = this.getRules();
		result = result * PRIME + ($rules == null ? 43 : $rules.hashCode());
		return result;
	}

	public ObfuscationRulesBuilder<C, RW> toBuilder()
	{
		return new ObfuscationRulesBuilder<C, RW>()
			.rules(this.rules == null ? java.util.Collections.emptyList() : this.rules);
	}

	@Override
	public String toString()
	{
		return "ObfuscationRules(rules=" + this.getRules() + ")";
	}

	public static class ObfuscationRulesBuilder<C, RW>
	{
		private ArrayList<ObfuscationRule<C, RW>> rules;

		ObfuscationRulesBuilder()
		{
		}

		public ObfuscationRules<C, RW> build()
		{
			List<ObfuscationRule<C, RW>> rules;
			switch (this.rules == null ? 0 : this.rules.size())
			{
				case 0 :
					rules = java.util.Collections.emptyList();
					break;
				case 1 :
					rules = java.util.Collections.singletonList(this.rules.get(0));
					break;
				default :
					rules = java.util.Collections
						.unmodifiableList(new ArrayList<ObfuscationRule<C, RW>>(this.rules));
			}

			return new ObfuscationRules<C, RW>(rules);
		}

		public ObfuscationRules.ObfuscationRulesBuilder<C, RW> clearRules()
		{
			if (this.rules != null)
				this.rules.clear();
			return this;
		}

		public ObfuscationRules.ObfuscationRulesBuilder<C, RW> rule(ObfuscationRule<C, RW> rule)
		{
			if (this.rules == null)
				this.rules = new ArrayList<ObfuscationRule<C, RW>>();
			this.rules.add(rule);
			return this;
		}

		public ObfuscationRules.ObfuscationRulesBuilder<C, RW> rules(
			Collection<? extends ObfuscationRule<C, RW>> rules)
		{
			if (this.rules == null)
				this.rules = new ArrayList<ObfuscationRule<C, RW>>();
			this.rules.addAll(rules);
			return this;
		}

		@Override
		public String toString()
		{
			return "ObfuscationRules.ObfuscationRulesBuilder(rules=" + this.rules + ")";
		}
	}
}
