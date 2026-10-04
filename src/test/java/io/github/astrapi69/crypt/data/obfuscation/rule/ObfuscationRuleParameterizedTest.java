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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationRule.ObfuscationRuleBuilder;

/**
 * Parameterized tests for the equals/hashCode contract, the builder and
 * {@link ObfuscationRule#toBuilder()} of {@link ObfuscationRule}
 */
class ObfuscationRuleParameterizedTest
{

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
	record EqualsCase(String description, ObfuscationRule<Character, Character> first,
		Object second, boolean expectedEqual) {
	}

	/**
	 * One pair of character and replacement
	 *
	 * @param character
	 *            the character to obfuscate
	 * @param replaceWith
	 *            the replacement
	 */
	record RuleCase(char character, char replaceWith) {
	}

	private static ObfuscationRule<Character, Character> withCharacterOnly(final char character)
	{
		ObfuscationRule<Character, Character> rule = new ObfuscationRule<>();
		rule.setCharacter(character);
		return rule;
	}

	private static ObfuscationRule<Character, Character> withReplaceWithOnly(final char replaceWith)
	{
		ObfuscationRule<Character, Character> rule = new ObfuscationRule<>();
		rule.setReplaceWith(replaceWith);
		return rule;
	}

	static Stream<EqualsCase> equalsCases()
	{
		ObfuscationRule<Character, Character> same = new ObfuscationRule<>('a', 'b');
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", new ObfuscationRule<>('a', 'b'), null, false),
			new EqualsCase("other type", new ObfuscationRule<>('a', 'b'), "ab", false),
			new EqualsCase("equal content", new ObfuscationRule<>('a', 'b'),
				new ObfuscationRule<>('a', 'b'), true),
			new EqualsCase("character differs", new ObfuscationRule<>('a', 'b'),
				new ObfuscationRule<>('x', 'b'), false),
			new EqualsCase("replace with differs", new ObfuscationRule<>('a', 'b'),
				new ObfuscationRule<>('a', 'y'), false),
			new EqualsCase("first character null", withReplaceWithOnly('b'),
				new ObfuscationRule<>('a', 'b'), false),
			new EqualsCase("second character null", new ObfuscationRule<>('a', 'b'),
				withReplaceWithOnly('b'), false),
			new EqualsCase("both characters null", withReplaceWithOnly('b'),
				withReplaceWithOnly('b'), true),
			new EqualsCase("first replace with null", withCharacterOnly('a'),
				new ObfuscationRule<>('a', 'b'), false),
			new EqualsCase("second replace with null", new ObfuscationRule<>('a', 'b'),
				withCharacterOnly('a'), false),
			new EqualsCase("both replace with null", withCharacterOnly('a'), withCharacterOnly('a'),
				true),
			new EqualsCase("both empty", new ObfuscationRule<>(), new ObfuscationRule<>(), true),
			new EqualsCase("empty versus populated", new ObfuscationRule<>(),
				new ObfuscationRule<>('a', 'b'), false));
	}

	/**
	 * Test method for {@link ObfuscationRule#equals(Object)} and {@link ObfuscationRule#hashCode()}
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
		if (testCase.second()instanceof ObfuscationRule<?, ?> other)
		{
			assertEquals(testCase.expectedEqual(), other.equals(testCase.first()),
				"symmetry: " + testCase.description());
			if (testCase.expectedEqual())
			{
				assertEquals(testCase.first().hashCode(), other.hashCode(), testCase.description());
			}
		}
	}

	static Stream<RuleCase> ruleCases()
	{
		return Stream.of(new RuleCase('a', 'b'), new RuleCase('x', 'y'), new RuleCase('1', '2'),
			new RuleCase('$', '%'));
	}

	/**
	 * Test method for {@link ObfuscationRule#toBuilder()} and
	 * {@link ObfuscationRuleBuilder#toString()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCases")
	void toBuilderRoundTrip(final RuleCase testCase)
	{
		ObfuscationRule<Character, Character> original = new ObfuscationRule<>(testCase.character(),
			testCase.replaceWith());

		ObfuscationRuleBuilder<Character, Character> builder = original.toBuilder();
		ObfuscationRule<Character, Character> copy = builder.build();

		assertNotSame(original, copy);
		assertEquals(original, copy);
		assertEquals(original.hashCode(), copy.hashCode());
		assertEquals("ObfuscationRule.ObfuscationRuleBuilder(character=" + testCase.character()
			+ ", replaceWith=" + testCase.replaceWith() + ")", builder.toString());
		// a modified builder yields a different rule and leaves the original untouched
		ObfuscationRule<Character, Character> modified = builder.replaceWith('~').build();
		assertNotEquals(original, modified);
		assertEquals(testCase.replaceWith(), original.getReplaceWith());
	}

	/**
	 * Test method for the non-null contract of {@link ObfuscationRule} and its builder
	 */
	@Test
	void nonNullContract()
	{
		ObfuscationRule<Character, Character> rule = new ObfuscationRule<>('a', 'b');
		ObfuscationRuleBuilder<Character, Character> builder = ObfuscationRule.builder();

		assertThrows(NullPointerException.class, () -> new ObfuscationRule<>(null, 'b'));
		assertThrows(NullPointerException.class, () -> new ObfuscationRule<>('a', null));
		assertThrows(NullPointerException.class, () -> rule.setCharacter(null));
		assertThrows(NullPointerException.class, () -> rule.setReplaceWith(null));
		assertThrows(NullPointerException.class, () -> builder.character(null));
		assertThrows(NullPointerException.class, () -> builder.replaceWith(null));
		assertThrows(NullPointerException.class, builder::build);
	}
}
