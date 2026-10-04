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
package io.github.astrapi69.crypt.data.obfuscation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.crypt.data.obfuscation.rule.CharacterObfuscationOperationRule;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationRule;
import io.github.astrapi69.crypt.data.obfuscation.rules.CharacterObfuscationRules;
import io.github.astrapi69.crypt.data.obfuscation.rules.ObfuscationBiMapRules;
import io.github.astrapi69.crypt.data.obfuscation.rules.ObfuscationRules;

/**
 * Pins the {@code hashCode()} formula (Lombok style: prime 59, 43 for null, 79/97 for booleans) and
 * the {@code toString()} layout of the obfuscation model classes. Rules are persisted and compared
 * across runs, so the values must not drift silently
 */
class ObfuscationHashCodeAndToStringContractParameterizedTest
{

	private static final int PRIME = 59;
	private static final int NULL_HASH = 43;

	/**
	 * One object together with its independently computed reference hash and the expected
	 * {@code toString()} value
	 *
	 * @param description
	 *            what the case covers
	 * @param object
	 *            the object under test
	 * @param expectedHashCode
	 *            the reference hash computed in the test
	 * @param expectedToString
	 *            the expected string representation
	 */
	record ContractCase(String description, Object object, int expectedHashCode,
		String expectedToString) {
	}

	private static int hashOf(final Object value)
	{
		return value == null ? NULL_HASH : value.hashCode();
	}

	private static int referenceHash(final ObfuscationOperationRule<?, ?> rule)
	{
		int result = 1;
		result = result * PRIME + hashOf(rule.getCharacter());
		result = result * PRIME + hashOf(rule.getIndexes());
		result = result * PRIME + (rule.isInverted() ? 79 : 97);
		result = result * PRIME + hashOf(rule.getOperatedCharacter());
		result = result * PRIME + hashOf(rule.getOperation());
		result = result * PRIME + hashOf(rule.getReplaceWith());
		return result;
	}

	private static int referenceHash(final ObfuscationRule<?, ?> rule)
	{
		int result = 1;
		result = result * PRIME + hashOf(rule.getCharacter());
		result = result * PRIME + hashOf(rule.getReplaceWith());
		return result;
	}

	private static int referenceHash(final ObfuscationRules<?, ?> rules)
	{
		return PRIME + hashOf(rules.getRules());
	}

	private static int referenceHash(final ObfuscationBiMapRules<?, ?> rules)
	{
		return PRIME + hashOf(rules.getObfuscationRules());
	}

	static Stream<ContractCase> contractCases()
	{
		ObfuscationOperationRule<Character, Character> emptyOperationRule = new ObfuscationOperationRule<>();
		ObfuscationOperationRule<Character, Character> invertedOperationRule = new ObfuscationOperationRule<>(
			'a', Set.of(1, 3), true, Optional.of('A'), Operation.UPPERCASE, 'b');
		ObfuscationOperationRule<Character, Character> plainOperationRule = new ObfuscationOperationRule<>(
			'a', Set.of(), false, Optional.empty(), Operation.NONE, 'b');
		CharacterObfuscationOperationRule characterOperationRule = new CharacterObfuscationOperationRule(
			'x', Set.of(0), false, Optional.empty(), Operation.UPPERCASE, 'y');

		ObfuscationRule<Character, Character> emptyRule = new ObfuscationRule<>();
		ObfuscationRule<Character, Character> rule = new ObfuscationRule<>('a', 'b');

		ObfuscationRules<Character, Character> emptyRules = new ObfuscationRules<>();
		ObfuscationRules<Character, Character> rules = new ObfuscationRules<>(List.of(rule));

		BiMap<Character, Character> biMap = HashBiMap.create();
		biMap.put('a', 'b');
		ObfuscationBiMapRules<Character, Character> biMapRules = new ObfuscationBiMapRules<>(biMap);
		CharacterObfuscationRules characterRules = new CharacterObfuscationRules(biMap);

		return Stream.of(
			new ContractCase("empty operation rule", emptyOperationRule,
				referenceHash(emptyOperationRule),
				"ObfuscationOperationRule(character=null, indexes=[], inverted=false, "
					+ "operatedCharacter=Optional.empty, operation=NONE, replaceWith=null)"),
			new ContractCase("inverted operation rule", invertedOperationRule,
				referenceHash(invertedOperationRule),
				"ObfuscationOperationRule(character=a, indexes=" + Set.of(1, 3)
					+ ", inverted=true, operatedCharacter=Optional[A], operation=UPPERCASE, "
					+ "replaceWith=b)"),
			new ContractCase("plain operation rule", plainOperationRule,
				referenceHash(plainOperationRule),
				"ObfuscationOperationRule(character=a, indexes=[], inverted=false, "
					+ "operatedCharacter=Optional.empty, operation=NONE, replaceWith=b)"),
			new ContractCase("character operation rule", characterOperationRule,
				referenceHash(characterOperationRule),
				"CharacterObfuscationOperationRule(super=ObfuscationOperationRule(character=x, "
					+ "indexes=[0], inverted=false, operatedCharacter=Optional[X], "
					+ "operation=UPPERCASE, replaceWith=y))"),
			new ContractCase("empty rule", emptyRule, referenceHash(emptyRule),
				"ObfuscationRule(character=null, replaceWith=null)"),
			new ContractCase("rule", rule, referenceHash(rule),
				"ObfuscationRule(character=a, replaceWith=b)"),
			new ContractCase("empty rules", emptyRules, referenceHash(emptyRules),
				"ObfuscationRules(rules=" + emptyRules.getRules() + ")"),
			new ContractCase("rules", rules, referenceHash(rules),
				"ObfuscationRules(rules=[ObfuscationRule(character=a, replaceWith=b)])"),
			new ContractCase("bimap rules", biMapRules, referenceHash(biMapRules),
				"ObfuscationBiMapRules(obfuscationRules={a=b})"),
			new ContractCase("character rules", characterRules, referenceHash(characterRules),
				"CharacterObfuscationRules(super=ObfuscationBiMapRules(obfuscationRules={a=b}))"));
	}

	/**
	 * Test method for the {@code hashCode()} and {@code toString()} contract of the obfuscation
	 * model classes
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("contractCases")
	void hashCodeAndToStringFollowTheContract(final ContractCase testCase)
	{
		assertEquals(testCase.expectedHashCode(), testCase.object().hashCode(),
			testCase.description());
		assertNotEquals(0, testCase.object().hashCode(), testCase.description());
		assertEquals(testCase.expectedToString(), testCase.object().toString(),
			testCase.description());
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#hashCode()}: the inverted flag alone must
	 * change the hash (79 versus 97)
	 */
	@Test
	void invertedFlagChangesOperationRuleHash()
	{
		ObfuscationOperationRule<Character, Character> inverted = new ObfuscationOperationRule<>(
			'a', Set.of(), true, Optional.empty(), Operation.NONE, 'b');
		ObfuscationOperationRule<Character, Character> notInverted = new ObfuscationOperationRule<>(
			'a', Set.of(), false, Optional.empty(), Operation.NONE, 'b');
		assertNotEquals(inverted.hashCode(), notInverted.hashCode());
		assertEquals(97 - 79,
			(notInverted.hashCode() - inverted.hashCode()) / (PRIME * PRIME * PRIME));
	}

	/**
	 * Test method for {@link ObfuscationBiMapRules#equals(Object)} with foreign objects
	 */
	@Test
	void biMapRulesEqualsRejectsForeignObjects()
	{
		BiMap<Character, Character> biMap = HashBiMap.create();
		biMap.put('a', 'b');
		ObfuscationBiMapRules<Character, Character> rules = new ObfuscationBiMapRules<>(biMap);

		assertFalse(rules.equals(null));
		assertFalse(rules.equals("ObfuscationBiMapRules"));
		assertFalse(rules.equals(biMap));
		assertTrue(rules.equals(new ObfuscationBiMapRules<>(HashBiMap.create(biMap))));
		assertTrue(rules.equals(rules));
	}
}
