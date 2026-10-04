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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationRule;
import io.github.astrapi69.crypt.data.obfuscation.rules.ObfuscationRules.ObfuscationRulesBuilder;

/**
 * Parameterized tests for {@link ObfuscationRules} and its builder
 */
class ObfuscationRulesParameterizedTest
{

	/**
	 * The number of rules to put into the builder
	 *
	 * @param ruleCount
	 *            the number of rules
	 */
	record RuleCountCase(int ruleCount) {
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
	record EqualsCase(String description, ObfuscationRules<Character, Character> first,
		Object second, boolean expectedEqual) {
	}

	static List<ObfuscationRule<Character, Character>> newRules(final int count)
	{
		List<ObfuscationRule<Character, Character>> rules = new ArrayList<>();
		for (int i = 0; i < count; i++)
		{
			rules.add(new ObfuscationRule<>((char)('a' + i), (char)('A' + i)));
		}
		return rules;
	}

	static ObfuscationRules<Character, Character> newObfuscationRules(final int count)
	{
		return ObfuscationRules.<Character, Character> builder().rules(newRules(count)).build();
	}

	static Stream<RuleCountCase> ruleCountCases()
	{
		return Stream.of(new RuleCountCase(0), new RuleCountCase(1), new RuleCountCase(2),
			new RuleCountCase(5));
	}

	/**
	 * Test method for {@link ObfuscationRulesBuilder#rule(ObfuscationRule)} and
	 * {@link ObfuscationRulesBuilder#build()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCountCases")
	void buildWithSingleRuleAdditions(final RuleCountCase testCase)
	{
		List<ObfuscationRule<Character, Character>> rules = newRules(testCase.ruleCount());
		ObfuscationRulesBuilder<Character, Character> builder = ObfuscationRules.builder();
		rules.forEach(builder::rule);

		ObfuscationRules<Character, Character> actual = builder.build();

		assertEquals(rules, actual.getRules());
		assertEquals(testCase.ruleCount(), actual.getRules().size());
		// the built list is a read-only snapshot
		assertThrows(UnsupportedOperationException.class,
			() -> actual.getRules().add(new ObfuscationRule<>('x', 'y')));
	}

	/**
	 * Test method for {@link ObfuscationRulesBuilder#rules(java.util.Collection)}: adding a
	 * collection is equivalent to adding the rules one by one and to the constructor
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCountCases")
	void buildWithRulesCollectionIsEquivalent(final RuleCountCase testCase)
	{
		List<ObfuscationRule<Character, Character>> rules = newRules(testCase.ruleCount());
		ObfuscationRulesBuilder<Character, Character> oneByOne = ObfuscationRules.builder();
		rules.forEach(oneByOne::rule);

		ObfuscationRules<Character, Character> viaCollection = ObfuscationRules
			.<Character, Character> builder().rules(rules).build();
		ObfuscationRules<Character, Character> viaSingleRules = oneByOne.build();
		ObfuscationRules<Character, Character> viaConstructor = new ObfuscationRules<>(rules);

		assertEquals(viaSingleRules, viaCollection);
		assertEquals(viaConstructor, viaCollection);
		assertEquals(viaSingleRules.hashCode(), viaCollection.hashCode());
		assertEquals(viaSingleRules.toString(), viaCollection.toString());
		assertTrue(viaCollection.toString().startsWith("ObfuscationRules(rules="));
	}

	/**
	 * Test method for {@link ObfuscationRulesBuilder#rules(java.util.Collection)}: a second call
	 * appends to the rules already in the builder instead of replacing them
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCountCases")
	void rulesCollectionAppendsToExistingRules(final RuleCountCase testCase)
	{
		List<ObfuscationRule<Character, Character>> first = newRules(testCase.ruleCount());
		List<ObfuscationRule<Character, Character>> second = List
			.of(new ObfuscationRule<>('x', 'X'), new ObfuscationRule<>('y', 'Y'));
		List<ObfuscationRule<Character, Character>> expected = new ArrayList<>(first);
		expected.addAll(second);

		ObfuscationRules<Character, Character> actual = ObfuscationRules
			.<Character, Character> builder().rules(first).rules(second).build();

		assertEquals(expected, actual.getRules());
		assertEquals(testCase.ruleCount() + second.size(), actual.getRules().size());
	}

	/**
	 * Test method for {@link ObfuscationRules#toBuilder()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCountCases")
	void toBuilderRoundTrip(final RuleCountCase testCase)
	{
		ObfuscationRules<Character, Character> original = newObfuscationRules(testCase.ruleCount());

		ObfuscationRules<Character, Character> copy = original.toBuilder().build();

		assertNotSame(original, copy);
		assertEquals(original, copy);
		assertEquals(original.hashCode(), copy.hashCode());
		// extending the copied builder leaves the original untouched
		ObfuscationRules<Character, Character> extended = original.toBuilder()
			.rule(new ObfuscationRule<>('z', 'Z')).build();
		assertEquals(testCase.ruleCount() + 1, extended.getRules().size());
		assertEquals(testCase.ruleCount(), original.getRules().size());
		assertNotEquals(original, extended);
	}

	/**
	 * Test method for {@link ObfuscationRulesBuilder#clearRules()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCountCases")
	void clearRulesEmptiesTheBuilder(final RuleCountCase testCase)
	{
		ObfuscationRules<Character, Character> cleared = ObfuscationRules
			.<Character, Character> builder().rules(newRules(testCase.ruleCount())).clearRules()
			.build();

		assertTrue(cleared.getRules().isEmpty());
		assertEquals(ObfuscationRules.<Character, Character> builder().build(), cleared);
	}

	/**
	 * Test method for {@link ObfuscationRulesBuilder#toString()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("ruleCountCases")
	void builderToStringReflectsContent(final RuleCountCase testCase)
	{
		List<ObfuscationRule<Character, Character>> rules = newRules(testCase.ruleCount());
		ObfuscationRulesBuilder<Character, Character> builder = ObfuscationRules
			.<Character, Character> builder().rules(rules);

		String actual = builder.toString();

		assertTrue(actual.startsWith("ObfuscationRules.ObfuscationRulesBuilder(rules="), actual);
		rules.forEach(rule -> assertTrue(actual.contains(rule.toString()), actual));
	}

	/**
	 * Test method for {@link ObfuscationRulesBuilder#clearRules()} and
	 * {@link ObfuscationRulesBuilder#toString()} on a builder that never received a rule
	 */
	@Test
	void freshBuilder()
	{
		ObfuscationRulesBuilder<Character, Character> builder = ObfuscationRules.builder();

		assertEquals("ObfuscationRules.ObfuscationRulesBuilder(rules=null)", builder.toString());
		assertTrue(builder.clearRules().build().getRules().isEmpty());
	}

	/**
	 * Test method for {@link ObfuscationRules#toBuilder()} on an instance without a rules list
	 */
	@Test
	void toBuilderWithoutRulesList()
	{
		ObfuscationRules<Character, Character> withoutRules = new ObfuscationRules<>();
		assertNull(withoutRules.getRules());

		ObfuscationRules<Character, Character> rebuilt = withoutRules.toBuilder().build();

		assertNotNull(rebuilt.getRules());
		assertTrue(rebuilt.getRules().isEmpty());
	}

	static Stream<EqualsCase> equalsCases()
	{
		ObfuscationRules<Character, Character> same = newObfuscationRules(2);
		ObfuscationRules<Character, Character> withoutRules = new ObfuscationRules<>();
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", newObfuscationRules(2), null, false),
			new EqualsCase("other type", newObfuscationRules(2), "foo", false),
			new EqualsCase("equal content", newObfuscationRules(2), newObfuscationRules(2), true),
			new EqualsCase("different size", newObfuscationRules(2), newObfuscationRules(3), false),
			new EqualsCase("null rules versus empty rules", withoutRules, newObfuscationRules(0),
				false),
			new EqualsCase("empty rules versus null rules", newObfuscationRules(0),
				new ObfuscationRules<>(), false),
			new EqualsCase("both without rules", withoutRules, new ObfuscationRules<>(), true),
			new EqualsCase("null rules set explicitly", withoutRules, new ObfuscationRules<>(null),
				true),
			new EqualsCase("empty list versus empty unmodifiable list",
				new ObfuscationRules<>(new ArrayList<>()),
				new ObfuscationRules<>(Collections.emptyList()), true));
	}

	/**
	 * Test method for {@link ObfuscationRules#equals(Object)} and
	 * {@link ObfuscationRules#hashCode()}
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
		if (testCase.second()instanceof ObfuscationRules<?, ?> other)
		{
			assertEquals(testCase.expectedEqual(), other.equals(testCase.first()),
				"symmetry: " + testCase.description());
			if (testCase.expectedEqual())
			{
				assertEquals(testCase.first().hashCode(), other.hashCode(), testCase.description());
			}
		}
	}
}
