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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule.ObfuscationOperationRuleBuilder;

/**
 * Parameterized tests for the equals/hashCode contract, the builder and
 * {@link ObfuscationOperationRule#toBuilder()} of {@link ObfuscationOperationRule}
 */
class ObfuscationOperationRuleEqualsParameterizedTest
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
	record EqualsCase(String description, ObfuscationOperationRule<Character, String> first,
		Object second, boolean expectedEqual) {
	}

	/**
	 * One full set of builder values
	 *
	 * @param character
	 *            the character to obfuscate
	 * @param indexes
	 *            the indexes
	 * @param inverted
	 *            the inverted flag
	 * @param operatedCharacter
	 *            the operated character
	 * @param operation
	 *            the operation
	 * @param replaceWith
	 *            the replacement
	 */
	record BuilderCase(Character character, Set<Integer> indexes, boolean inverted,
		Optional<Character> operatedCharacter, Operation operation, String replaceWith) {
	}

	private static ObfuscationOperationRule<Character, String> newRule()
	{
		return ObfuscationOperationRule.<Character, String> builder().character('a')
			.replaceWith("bc").operation(Operation.UPPERCASE).indexes(SetFactory.newHashSet(0, 2))
			.inverted(false).operatedCharacter(Optional.empty()).build();
	}

	private static ObfuscationOperationRule<Character, String> newRule(
		final Consumer<ObfuscationOperationRule<Character, String>> modifier)
	{
		ObfuscationOperationRule<Character, String> rule = newRule();
		modifier.accept(rule);
		return rule;
	}

	private static ObfuscationOperationRule<Character, String> allFieldsNull()
	{
		ObfuscationOperationRule<Character, String> rule = new ObfuscationOperationRule<>();
		rule.setCharacter(null);
		rule.setIndexes(null);
		rule.setOperatedCharacter(null);
		rule.setOperation(null);
		rule.setReplaceWith(null);
		return rule;
	}

	static Stream<EqualsCase> equalsCases()
	{
		ObfuscationOperationRule<Character, String> same = newRule();
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", newRule(), null, false),
			new EqualsCase("other type", newRule(), "a", false),
			new EqualsCase("identical copy", newRule(), newRule(), true),
			new EqualsCase("character differs", newRule(), newRule(rule -> rule.setCharacter('b')),
				false),
			new EqualsCase("first character null", newRule(rule -> rule.setCharacter(null)),
				newRule(), false),
			new EqualsCase("second character null", newRule(),
				newRule(rule -> rule.setCharacter(null)), false),
			new EqualsCase("both characters null", newRule(rule -> rule.setCharacter(null)),
				newRule(rule -> rule.setCharacter(null)), true),
			new EqualsCase("indexes differ", newRule(),
				newRule(rule -> rule.setIndexes(SetFactory.newHashSet(1))), false),
			new EqualsCase("first indexes null", newRule(rule -> rule.setIndexes(null)), newRule(),
				false),
			new EqualsCase("second indexes null", newRule(), newRule(rule -> rule.setIndexes(null)),
				false),
			new EqualsCase("both indexes null", newRule(rule -> rule.setIndexes(null)),
				newRule(rule -> rule.setIndexes(null)), true),
			new EqualsCase("inverted differs", newRule(), newRule(rule -> rule.setInverted(true)),
				false),
			new EqualsCase("operated character differs", newRule(),
				newRule(rule -> rule.setOperatedCharacter(Optional.of('A'))), false),
			new EqualsCase("first operated character null",
				newRule(rule -> rule.setOperatedCharacter(null)), newRule(), false),
			new EqualsCase("second operated character null", newRule(),
				newRule(rule -> rule.setOperatedCharacter(null)), false),
			new EqualsCase("both operated characters null",
				newRule(rule -> rule.setOperatedCharacter(null)),
				newRule(rule -> rule.setOperatedCharacter(null)), true),
			new EqualsCase("operation differs", newRule(),
				newRule(rule -> rule.setOperation(Operation.LOWERCASE)), false),
			new EqualsCase("first operation null", newRule(rule -> rule.setOperation(null)),
				newRule(), false),
			new EqualsCase("second operation null", newRule(),
				newRule(rule -> rule.setOperation(null)), false),
			new EqualsCase("both operations null", newRule(rule -> rule.setOperation(null)),
				newRule(rule -> rule.setOperation(null)), true),
			new EqualsCase("replace with differs", newRule(),
				newRule(rule -> rule.setReplaceWith("xy")), false),
			new EqualsCase("first replace with null", newRule(rule -> rule.setReplaceWith(null)),
				newRule(), false),
			new EqualsCase("second replace with null", newRule(),
				newRule(rule -> rule.setReplaceWith(null)), false),
			new EqualsCase("both replace with null", newRule(rule -> rule.setReplaceWith(null)),
				newRule(rule -> rule.setReplaceWith(null)), true),
			new EqualsCase("all fields null", allFieldsNull(), allFieldsNull(), true),
			new EqualsCase("all fields null versus populated", allFieldsNull(), newRule(), false));
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#equals(Object)} and
	 * {@link ObfuscationOperationRule#hashCode()}
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
		if (testCase.second()instanceof ObfuscationOperationRule<?, ?> other)
		{
			assertEquals(testCase.expectedEqual(), other.equals(testCase.first()),
				"symmetry: " + testCase.description());
			if (testCase.expectedEqual())
			{
				assertEquals(testCase.first().hashCode(), other.hashCode(), testCase.description());
			}
		}
	}

	static Stream<BuilderCase> builderCases()
	{
		return Stream.of(
			new BuilderCase('a', SetFactory.newHashSet(0, 2), false, Optional.empty(),
				Operation.UPPERCASE, "bc"),
			new BuilderCase('Z', SetFactory.newHashSet(1), true, Optional.of('z'),
				Operation.LOWERCASE, "x"),
			new BuilderCase('7', SetFactory.newHashSet(), true, Optional.empty(), Operation.NONE,
				"seven"));
	}

	/**
	 * Test method for every setter of {@link ObfuscationOperationRuleBuilder},
	 * {@link ObfuscationOperationRule#toBuilder()} and
	 * {@link ObfuscationOperationRuleBuilder#toString()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("builderCases")
	void builderSetsEveryField(final BuilderCase testCase)
	{
		ObfuscationOperationRule<Character, String> actual = ObfuscationOperationRule
			.<Character, String> builder().character(testCase.character())
			.indexes(testCase.indexes()).inverted(testCase.inverted())
			.operatedCharacter(testCase.operatedCharacter()).operation(testCase.operation())
			.replaceWith(testCase.replaceWith()).build();

		assertEquals(testCase.character(), actual.getCharacter());
		assertEquals(testCase.indexes(), actual.getIndexes());
		assertEquals(testCase.inverted(), actual.isInverted());
		assertEquals(testCase.operatedCharacter(), actual.getOperatedCharacter());
		assertEquals(testCase.operation(), actual.getOperation());
		assertEquals(testCase.replaceWith(), actual.getReplaceWith());

		ObfuscationOperationRule<Character, String> copy = actual.toBuilder().build();
		assertNotSame(actual, copy);
		assertEquals(actual, copy);
		assertEquals(actual.hashCode(), copy.hashCode());
		assertEquals(actual.toString(), copy.toString());

		String builderString = actual.toBuilder().toString();
		assertTrue(builderString
			.startsWith("ObfuscationOperationRule.ObfuscationOperationRuleBuilder(character="
				+ testCase.character()),
			builderString);
		assertTrue(builderString.contains("inverted=" + testCase.inverted()), builderString);
		assertTrue(builderString.contains("operatedCharacter=" + testCase.operatedCharacter()),
			builderString);
		assertTrue(builderString.contains("operation=" + testCase.operation()), builderString);
		assertTrue(builderString.contains("replaceWith=" + testCase.replaceWith() + ")"),
			builderString);
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#toBuilder()}: changes on the builder do not
	 * leak into the original
	 */
	@Test
	void toBuilderModificationsDoNotAffectOriginal()
	{
		ObfuscationOperationRule<Character, String> original = newRule();

		ObfuscationOperationRule<Character, String> modified = original.toBuilder().inverted(true)
			.operatedCharacter(Optional.of('A')).build();

		assertFalse(original.isInverted());
		assertEquals(Optional.empty(), original.getOperatedCharacter());
		assertTrue(modified.isInverted());
		assertEquals(Optional.of('A'), modified.getOperatedCharacter());
		assertNotEquals(original, modified);
	}

	/**
	 * Test method for the non-null contract of {@link ObfuscationOperationRuleBuilder}
	 */
	@Test
	void builderRejectsNullCharacterAndReplaceWith()
	{
		ObfuscationOperationRuleBuilder<Character, String> builder = ObfuscationOperationRule
			.builder();

		assertThrows(NullPointerException.class, () -> builder.character(null));
		assertThrows(NullPointerException.class, () -> builder.replaceWith(null));
		assertThrows(NullPointerException.class, () -> builder.build());
	}
}
