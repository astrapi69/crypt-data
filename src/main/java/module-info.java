/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
module crypt.data
{
	requires crypt.api;
	requires lombok;
	requires silly.collection;
	requires com.google.common;
	requires org.apache.commons.codec;
	requires org.apache.commons.lang3;
	requires org.bouncycastle.provider;
	requires java.logging;
	requires org.bouncycastle.pkix;
	requires silly.strings;
	requires file.worker;
	requires java.xml.bind;
	requires io.github.astrapisixtynine.throwable;
	requires org.checkerframework.checker.qual;

	exports io.github.astrapi69.crypt.data.algorithm;
	exports io.github.astrapi69.crypt.data.blockchain;
	exports io.github.astrapi69.crypt.data.certificate;
	exports io.github.astrapi69.crypt.data.factory;
	exports io.github.astrapi69.crypt.data.hash;
	exports io.github.astrapi69.crypt.data.hex;
	exports io.github.astrapi69.crypt.data.key.reader;
	exports io.github.astrapi69.crypt.data.key.writer;
	exports io.github.astrapi69.crypt.data.model;
	exports io.github.astrapi69.crypt.data.obfuscation.rule;
	exports io.github.astrapi69.crypt.data.obfuscation.rules;
}