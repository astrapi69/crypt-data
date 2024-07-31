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

import java.util.Optional;
import java.util.Set;

import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;

/**
 * The class {@link CharacterObfuscationOperationRule} builds a complex rule for obfuscating a
 * single character It extends the {@link ObfuscationOperationRule} to provide specific rules for
 * character obfuscation
 */
public class CharacterObfuscationOperationRule
	extends
		ObfuscationOperationRule<Character, Character>
{

	/**
	 * Instantiates a new {@link CharacterObfuscationOperationRule} with no parameters
	 */
	public CharacterObfuscationOperationRule()
	{
	}

	/**
	 * Instantiates a new {@link CharacterObfuscationOperationRule} with the specified parameters
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
	public CharacterObfuscationOperationRule(Character character, Set<Integer> indexes,
		boolean inverted, Optional<Character> operatedCharacter, Operation operation,
		Character replaceWith)
	{
		super(character, indexes, inverted, operatedCharacter, operation, replaceWith);
		if (operation != null)
		{
			setOperatedCharacter(Optional.of(Operation.operate(character, operation)));
		}
	}

	/** {@inheritDoc} */
	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof CharacterObfuscationOperationRule))
			return false;
		final CharacterObfuscationOperationRule other = (CharacterObfuscationOperationRule)o;
		return super.equals(o);
	}

	/** {@inheritDoc} */
	@Override
	public int hashCode()
	{
		int result = super.hashCode();
		return result;
	}

	/** {@inheritDoc} */
	@Override
	public String toString()
	{
		return "CharacterObfuscationOperationRule(super=" + super.toString() + ")";
	}
}
