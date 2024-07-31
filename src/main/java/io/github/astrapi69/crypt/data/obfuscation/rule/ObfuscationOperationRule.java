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
package io.github.astrapi69.crypt.data.obfuscation.rule;

import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;

/**
 * The class {@link ObfuscationOperationRule} builds a complex rule for obfuscating a single
 * character
 *
 * @param <C>
 *            the type of character to be obfuscated
 * @param <RW>
 *            the type of character(s) that will replace the original character
 */
public class ObfuscationOperationRule<C, RW> implements Serializable
{

	/** The Constant serialVersionUID */
	private static final long serialVersionUID = 1L;

	/** The character to be obfuscated */
	private C character;

	/** The index where this rule will execute */
	private Set<Integer> indexes = SetFactory.newHashSet();

	/** The flag that shows if the character is inverted with replaceWith */
	private boolean inverted;

	/** The operated character */
	private Optional<C> operatedCharacter = Optional.empty();

	/** The type of operation for the obfuscation */
	private Operation operation = Operation.NONE;

	/** The character(s) that will be replaced with */
	private RW replaceWith;

	/**
	 * Instantiates a new {@link ObfuscationOperationRule} with no parameters
	 */
	public ObfuscationOperationRule()
	{
	}

	/**
	 * Instantiates a new {@link ObfuscationOperationRule} with the specified parameters
	 *
	 * @param character
	 *            the character to be obfuscated
	 * @param indexes
	 *            the set of indexes to apply the obfuscation
	 * @param inverted
	 *            if true, inverts the obfuscation rule
	 * @param operatedCharacter
	 *            the optional character that results from the operation
	 * @param operation
	 *            the operation to be applied for obfuscation
	 * @param replaceWith
	 *            the character to replace with after the operation
	 */
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

	/**
	 * Creates a new builder for {@link ObfuscationOperationRule}
	 *
	 * @param <C>
	 *            the type of character to be obfuscated
	 * @param <RW>
	 *            the type of character(s) that will replace the original character
	 * @return a new builder for {@link ObfuscationOperationRule}
	 */
	public static <C, RW> ObfuscationOperationRuleBuilder<C, RW> builder()
	{
		return new ObfuscationOperationRuleBuilder<>();
	}


	/** {@inheritDoc} */
	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof ObfuscationOperationRule))
			return false;
		final ObfuscationOperationRule<?, ?> other = (ObfuscationOperationRule<?, ?>)o;
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
		return this$replaceWith == null
			? other$replaceWith == null
			: this$replaceWith.equals(other$replaceWith);
	}

	/**
	 * Gets the character to be obfuscated
	 *
	 * @return the character to be obfuscated
	 */
	public C getCharacter()
	{
		return this.character;
	}

	/**
	 * Sets the character to be obfuscated
	 *
	 * @param character
	 *            the new character to be obfuscated
	 */
	public void setCharacter(C character)
	{
		this.character = character;
	}

	/**
	 * Gets the indexes where this rule will execute
	 *
	 * @return the indexes where this rule will execute
	 */
	public Set<Integer> getIndexes()
	{
		return this.indexes;
	}

	/**
	 * Sets the indexes where this rule will execute
	 *
	 * @param indexes
	 *            the new indexes where this rule will execute
	 */
	public void setIndexes(Set<Integer> indexes)
	{
		this.indexes = indexes;
	}

	/**
	 * Gets the optional character that results from the operation
	 *
	 * @return the optional character that results from the operation
	 */
	public Optional<C> getOperatedCharacter()
	{
		return this.operatedCharacter;
	}

	/**
	 * Sets the optional character that results from the operation
	 *
	 * @param operatedCharacter
	 *            the new optional character that results from the operation
	 */
	public void setOperatedCharacter(Optional<C> operatedCharacter)
	{
		this.operatedCharacter = operatedCharacter;
	}

	/**
	 * Gets the operation to be applied for obfuscation
	 *
	 * @return the operation to be applied for obfuscation
	 */
	public Operation getOperation()
	{
		return this.operation;
	}

	/**
	 * Sets the operation to be applied for obfuscation
	 *
	 * @param operation
	 *            the new operation to be applied for obfuscation
	 */
	public void setOperation(Operation operation)
	{
		this.operation = operation;
	}

	/**
	 * Gets the character(s) that will be replaced with
	 *
	 * @return the character(s) that will be replaced with
	 */
	public RW getReplaceWith()
	{
		return this.replaceWith;
	}

	/**
	 * Sets the character(s) that will be replaced with
	 *
	 * @param replaceWith
	 *            the new character(s) that will be replaced with
	 */
	public void setReplaceWith(RW replaceWith)
	{
		this.replaceWith = replaceWith;
	}

	/** {@inheritDoc} */
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

	/**
	 * Checks if the character is inverted with replaceWith
	 *
	 * @return true if the character is inverted with replaceWith, false otherwise
	 */
	public boolean isInverted()
	{
		return this.inverted;
	}

	/**
	 * Sets if the character is inverted with replaceWith
	 *
	 * @param inverted
	 *            the new inverted status
	 */
	public void setInverted(boolean inverted)
	{
		this.inverted = inverted;
	}

	/**
	 * Creates a builder from the current {@link ObfuscationOperationRule}
	 *
	 * @return a builder with the current {@link ObfuscationOperationRule}'s values
	 */
	public ObfuscationOperationRuleBuilder<C, RW> toBuilder()
	{
		return new ObfuscationOperationRuleBuilder<C, RW>().character(this.character)
			.indexes(this.indexes).inverted(this.inverted).operatedCharacter(this.operatedCharacter)
			.operation(this.operation).replaceWith(this.replaceWith);
	}

	/** {@inheritDoc} */
	@Override
	public String toString()
	{
		return "ObfuscationOperationRule(character=" + this.getCharacter() + ", indexes="
			+ this.getIndexes() + ", inverted=" + this.isInverted() + ", operatedCharacter="
			+ this.getOperatedCharacter() + ", operation=" + this.getOperation() + ", replaceWith="
			+ this.getReplaceWith() + ")";
	}

	/**
	 * The builder class for {@link ObfuscationOperationRule}
	 *
	 * @param <C>
	 *            the type of character to be obfuscated
	 * @param <RW>
	 *            the type of character(s) that will replace the original character
	 */
	public static class ObfuscationOperationRuleBuilder<C, RW>
	{
		private C character;
		private Set<Integer> indexes = SetFactory.newHashSet();
		private boolean inverted;
		private Optional<C> operatedCharacter = Optional.empty();
		private Operation operation;
		private RW replaceWith;

		/**
		 * Instantiates a new {@link ObfuscationOperationRuleBuilder} with no parameters
		 */
		ObfuscationOperationRuleBuilder()
		{
		}

		/**
		 * Builds the {@link ObfuscationOperationRule}
		 *
		 * @return the built {@link ObfuscationOperationRule}
		 */
		public ObfuscationOperationRule<C, RW> build()
		{
			return new ObfuscationOperationRule<>(character, indexes, inverted, operatedCharacter,
				operation, replaceWith);
		}

		/**
		 * Sets the character to be obfuscated
		 *
		 * @param character
		 *            the new character to be obfuscated
		 * @return the builder instance
		 */
		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> character(
			C character)
		{
			Objects.requireNonNull(character);
			this.character = character;
			return this;
		}

		/**
		 * Sets the indexes where this rule will execute
		 *
		 * @param indexes
		 *            the new indexes where this rule will execute
		 * @return the builder instance
		 */
		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> indexes(
			Set<Integer> indexes)
		{
			this.indexes = indexes;
			return this;
		}

		/**
		 * Sets if the character is inverted with replaceWith
		 *
		 * @param inverted
		 *            the new inverted status
		 * @return the builder instance
		 */
		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> inverted(
			boolean inverted)
		{
			this.inverted = inverted;
			return this;
		}

		/**
		 * Sets the optional character that results from the operation
		 *
		 * @param operatedCharacter
		 *            the new optional character that results from the operation
		 * @return the builder instance
		 */
		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> operatedCharacter(
			Optional<C> operatedCharacter)
		{
			this.operatedCharacter = operatedCharacter;
			return this;
		}

		/**
		 * Sets the operation to be applied for obfuscation
		 *
		 * @param operation
		 *            the new operation to be applied for obfuscation
		 * @return the builder instance
		 */
		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> operation(
			Operation operation)
		{
			this.operation = operation;
			return this;
		}

		/**
		 * Sets the character(s) that will be replaced with
		 *
		 * @param replaceWith
		 *            the new character(s) that will be replaced with
		 * @return the builder instance
		 */
		public ObfuscationOperationRule.ObfuscationOperationRuleBuilder<C, RW> replaceWith(
			RW replaceWith)
		{
			Objects.requireNonNull(replaceWith);
			this.replaceWith = replaceWith;
			return this;
		}

		/** {@inheritDoc} */
		@Override
		public String toString()
		{
			return "ObfuscationOperationRule.ObfuscationOperationRuleBuilder(character="
				+ this.character + ", indexes=" + this.indexes + ", inverted=" + this.inverted
				+ ", operatedCharacter=" + this.operatedCharacter + ", operation=" + this.operation
				+ ", replaceWith=" + this.replaceWith + ")";
		}
	}
}
