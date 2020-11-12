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
import java.util.Optional;
import java.util.Set;

import de.alpharogroup.collections.set.SetFactory;

/**
 * The class {@link ObfuscationOperationRule} builds a complex rule for obfuscating a single
 * character.
 */
public class ObfuscationOperationRule<C, RW> implements Serializable
{

	public static class ObfuscationOperationRuleBuilder<C, RW>
	{
		private C character;
		private Set<Integer> indexes = SetFactory.newHashSet();
		private boolean inverted;
		private Optional<C> operatedCharacter = Optional.empty();
		private Operation operation;
		private RW replaceWith;

		ObfuscationOperationRuleBuilder()
		{
		}

		public ObfuscationOperationRule<C, RW> build()
		{
			return new ObfuscationOperationRule<C, RW>(character, indexes, inverted,
				operatedCharacter, operation, replaceWith);
		}

		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> character(
			C character)
		{
			Objects.requireNonNull(character);
			this.character = character;
			return this;
		}

		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> indexes(
			Set<Integer> indexes)
		{
			this.indexes = indexes;
			return this;
		}

		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> inverted(
			boolean inverted)
		{
			this.inverted = inverted;
			return this;
		}

		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> operatedCharacter(
			Optional<C> operatedCharacter)
		{
			this.operatedCharacter = operatedCharacter;
			return this;
		}

		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> operation(
			Operation operation)
		{
			this.operation = operation;
			return this;
		}

		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> replaceWith(
			RW replaceWith)
		{
			Objects.requireNonNull(replaceWith);
			this.replaceWith = replaceWith;
			return this;
		}

		@Override
		public String toString()
		{
			return "ObfuscationOperationRule.ObfuscationOperationRuleBuilder(character="
				+ this.character + ", indexes=" + this.indexes + ", inverted=" + this.inverted
				+ ", operatedCharacter=" + this.operatedCharacter + ", operation=" + this.operation
				+ ", replaceWith=" + this.replaceWith + ")";
		}
	}

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	public static <C, RW> ObfuscationOperationRuleBuilder<C, RW> builder()
	{
		return new ObfuscationOperationRuleBuilder<C, RW>();
	}

	/** The character. */
	private C character;
	/** The index where this rule will execute. */
	private Set<Integer> indexes = SetFactory.newHashSet();
	/** The flag that shows if the character is inverted with replaceWith. */
	private boolean inverted;
	/** The operated character. */
	private Optional<C> operatedCharacter = Optional.empty();

	/** The type of operation for the obfuscation. */
	private Operation operation = Operation.NONE;

	/** The character(s) that will be replaced with. */
	private RW replaceWith;

	public ObfuscationOperationRule()
	{
	}

	public ObfuscationOperationRule(C character, Set<Integer> indexes, boolean inverted,
		Optional<C> operatedCharacter, Operation operation, RW replaceWith)
	{
		Objects.requireNonNull(character);
		Objects.requireNonNull(replaceWith);
		this.character = character;
		this.indexes = indexes;
		this.inverted = inverted;
		this.operatedCharacter = operatedCharacter;
		this.operation = operation;
		this.replaceWith = replaceWith;
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof ObfuscationOperationRule;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof ObfuscationOperationRule))
			return false;
		final ObfuscationOperationRule<?, ?> other = (ObfuscationOperationRule<?, ?>)o;
		if (!other.canEqual(this))
			return false;
		final Object this$character = this.getCharacter();
		final Object other$character = other.getCharacter();
		if (this$character == null
			? other$character != null
			: !this$character.equals(other$character))
			return false;
		final Object this$indexes = this.getIndexes();
		final Object other$indexes = other.getIndexes();
		if (this$indexes == null ? other$indexes != null : !this$indexes.equals(other$indexes))
			return false;
		if (this.isInverted() != other.isInverted())
			return false;
		final Object this$operatedCharacter = this.getOperatedCharacter();
		final Object other$operatedCharacter = other.getOperatedCharacter();
		if (this$operatedCharacter == null
			? other$operatedCharacter != null
			: !this$operatedCharacter.equals(other$operatedCharacter))
			return false;
		final Object this$operation = this.getOperation();
		final Object other$operation = other.getOperation();
		if (this$operation == null
			? other$operation != null
			: !this$operation.equals(other$operation))
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

	public Set<Integer> getIndexes()
	{
		return this.indexes;
	}

	public Optional<C> getOperatedCharacter()
	{
		return this.operatedCharacter;
	}

	public Operation getOperation()
	{
		return this.operation;
	}

	public RW getReplaceWith()
	{
		return this.replaceWith;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $character = this.getCharacter();
		result = result * PRIME + ($character == null ? 43 : $character.hashCode());
		final Object $indexes = this.getIndexes();
		result = result * PRIME + ($indexes == null ? 43 : $indexes.hashCode());
		result = result * PRIME + (this.isInverted() ? 79 : 97);
		final Object $operatedCharacter = this.getOperatedCharacter();
		result = result * PRIME + ($operatedCharacter == null ? 43 : $operatedCharacter.hashCode());
		final Object $operation = this.getOperation();
		result = result * PRIME + ($operation == null ? 43 : $operation.hashCode());
		final Object $replaceWith = this.getReplaceWith();
		result = result * PRIME + ($replaceWith == null ? 43 : $replaceWith.hashCode());
		return result;
	}

	public boolean isInverted()
	{
		return this.inverted;
	}

	public void setCharacter(C character)
	{
		this.character = character;
	}

	public void setIndexes(Set<Integer> indexes)
	{
		this.indexes = indexes;
	}

	public void setInverted(boolean inverted)
	{
		this.inverted = inverted;
	}

	public void setOperatedCharacter(Optional<C> operatedCharacter)
	{
		this.operatedCharacter = operatedCharacter;
	}

	public void setOperation(Operation operation)
	{
		this.operation = operation;
	}

	public void setReplaceWith(RW replaceWith)
	{
		this.replaceWith = replaceWith;
	}

	public ObfuscationOperationRuleBuilder<C, RW> toBuilder()
	{
		return new ObfuscationOperationRuleBuilder<C, RW>().character(this.character)
			.indexes(this.indexes).inverted(this.inverted).operatedCharacter(this.operatedCharacter)
			.operation(this.operation).replaceWith(this.replaceWith);
	}

	@Override
	public String toString()
	{
		return "ObfuscationOperationRule(character=" + this.getCharacter() + ", indexes="
			+ this.getIndexes() + ", inverted=" + this.isInverted() + ", operatedCharacter="
			+ this.getOperatedCharacter() + ", operation=" + this.getOperation() + ", replaceWith="
			+ this.getReplaceWith() + ")";
	}
}
