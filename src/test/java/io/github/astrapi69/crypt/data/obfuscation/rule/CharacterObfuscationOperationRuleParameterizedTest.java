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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;

/**
 * Parameterized tests for the constructor and the equals/hashCode contract of
 * {@link CharacterObfuscationOperationRule}
 */
class CharacterObfuscationOperationRuleParameterizedTest
{

	/**
	 * One constructor invocation
	 *
	 * @param character
	 *            the character to obfuscate
	 * @param operation
	 *            the operation, may be null
	 * @param operatedCharacter
	 *            the operated character passed to the constructor
	 * @param expectedOperatedCharacter
	 *            the operated character the rule must expose afterwards
	 */
	record ConstructorCase(Character character, Operation operation,
		Optional<Character> operatedCharacter, Optional<Character> expectedOperatedCharacter) {
	}

	/**
	 * One equality comparison
	 *
	 * @param description
	 *            what is compared
	 * @param first
	 *            the object whose equals method is invoked
	 * @param second
	 *            the argument of the equals method
	 * @param expectedEqual
	 *            the expected result
	 */
	record EqualsCase(String description, CharacterObfuscationOperationRule first, Object second,
		boolean expectedEqual) {
	}

	private static CharacterObfuscationOperationRule newRule(final char character)
	{
		return new CharacterObfuscationOperationRule(character, SetFactory.newHashSet(0, 1), false,
			Optional.empty(), Operation.UPPERCASE, 'X');
	}

	static Stream<ConstructorCase> constructorCases()
	{
		return Stream.of(
			// with an operation the operated character is derived from the character
			new ConstructorCase('a', Operation.UPPERCASE, Optional.empty(), Optional.of('A')),
			new ConstructorCase('B', Operation.LOWERCASE, Optional.empty(), Optional.of('b')),
			new ConstructorCase('a', Operation.UPPERCASE, Optional.of('z'), Optional.of('A')),
			// without an operation the given operated character is kept as is
			new ConstructorCase('a', null, Optional.empty(), Optional.empty()),
			new ConstructorCase('a', null, Optional.of('z'), Optional.of('z')));
	}

	/**
	 * Test method for
	 * {@link CharacterObfuscationOperationRule#CharacterObfuscationOperationRule(Character, java.util.Set, boolean, Optional, Operation, Character)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("constructorCases")
	void constructorDerivesOperatedCharacter(final ConstructorCase testCase)
	{
		CharacterObfuscationOperationRule actual = new CharacterObfuscationOperationRule(
			testCase.character(), SetFactory.newHashSet(0), true, testCase.operatedCharacter(),
			testCase.operation(), 'x');

		assertEquals(testCase.character(), actual.getCharacter());
		assertEquals(testCase.operation(), actual.getOperation());
		assertEquals(testCase.expectedOperatedCharacter(), actual.getOperatedCharacter());
		assertEquals(Character.valueOf('x'), actual.getReplaceWith());
		assertTrue(actual.isInverted());
	}

	static Stream<EqualsCase> equalsCases()
	{
		CharacterObfuscationOperationRule same = newRule('a');
		ObfuscationOperationRule<Character, Character> plainRuleWithSameValues = new ObfuscationOperationRule<>(
			'a', SetFactory.newHashSet(0, 1), false, Optional.of('A'), Operation.UPPERCASE, 'X');
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", newRule('a'), null, false),
			new EqualsCase("other type", newRule('a'), "a", false),
			new EqualsCase("plain rule with the same values", newRule('a'), plainRuleWithSameValues,
				false),
			new EqualsCase("identical copy", newRule('a'), newRule('a'), true),
			new EqualsCase("character differs", newRule('a'), newRule('b'), false));
	}

	/**
	 * Test method for {@link CharacterObfuscationOperationRule#equals(Object)},
	 * {@link CharacterObfuscationOperationRule#hashCode()} and
	 * {@link CharacterObfuscationOperationRule#toString()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("equalsCases")
	void equalsContract(final EqualsCase testCase)
	{
		assertEquals(testCase.expectedEqual(), testCase.first().equals(testCase.second()),
			testCase.description());
		if (testCase.expectedEqual())
		{
			assertEquals(testCase.first().hashCode(), testCase.second().hashCode());
			assertEquals(testCase.first().toString(), testCase.second().toString());
		}
		assertTrue(testCase.first().toString()
			.startsWith("CharacterObfuscationOperationRule(super=ObfuscationOperationRule("));
	}
}
