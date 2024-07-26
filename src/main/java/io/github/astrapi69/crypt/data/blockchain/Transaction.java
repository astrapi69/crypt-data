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
package io.github.astrapi69.crypt.data.blockchain;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.api.blockchain.ITransaction;
import io.github.astrapi69.crypt.data.hash.HashExtensions;

/**
 * The class {@link Transaction} represents a transaction in a blockchain. It includes details such
 * as the sender's hash, a digital signature, the transaction text, a timestamp, and a hash
 * generated from these values.
 */
public class Transaction implements ITransaction
{

	/**
	 * The hash of the transaction, generated from the text, sender hash, signature, and timestamp.
	 */
	private byte[] hash;

	/** The hash of the sender. */
	private byte[] senderHash;

	/** The digital signature of the transaction. */
	private byte[] signature;

	/** The text or message of the transaction. */
	private String text;

	/** The timestamp when the transaction was created. */
	private long timestamp;

	/**
	 * Instantiates a new {@link Transaction} with no parameters.
	 */
	public Transaction()
	{
	}

	/**
	 * Instantiates a new {@link Transaction} with the specified text, sender hash, and signature.
	 * The hash is automatically generated using the SHA-256 algorithm.
	 *
	 * @param text
	 *            the text or message of the transaction
	 * @param senderHash
	 *            the hash of the sender
	 * @param signature
	 *            the digital signature of the transaction
	 */
	public Transaction(String text, byte[] senderHash, byte[] signature)
	{
		this.text = text;
		this.senderHash = senderHash;
		this.signature = signature;
		this.timestamp = System.currentTimeMillis();
		this.hash = HashExtensions.hash(text.getBytes(), senderHash, signature, timestamp,
			HashAlgorithm.SHA256);
	}

	/** {@inheritDoc} */
	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Transaction other))
			return false;
		if (!java.util.Arrays.equals(this.getHash(), other.getHash()))
			return false;
		if (!java.util.Arrays.equals(this.getSenderHash(), other.getSenderHash()))
			return false;
		if (!java.util.Arrays.equals(this.getSignature(), other.getSignature()))
			return false;
		final Object this$text = this.getText();
		final Object other$text = other.getText();
		if (this$text == null ? other$text != null : !this$text.equals(other$text))
			return false;
		return this.getTimestamp() == other.getTimestamp();
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getHash()
	{
		return this.hash;
	}

	/** {@inheritDoc} */
	@Override
	public void setHash(byte[] hash)
	{
		this.hash = hash;
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getSenderHash()
	{
		return this.senderHash;
	}

	/** {@inheritDoc} */
	@Override
	public void setSenderHash(byte[] senderHash)
	{
		this.senderHash = senderHash;
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getSignableData()
	{
		return text.getBytes();
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getSignature()
	{
		return this.signature;
	}

	/** {@inheritDoc} */
	@Override
	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}

	/** {@inheritDoc} */
	@Override
	public String getText()
	{
		return this.text;
	}

	/** {@inheritDoc} */
	@Override
	public void setText(String text)
	{
		this.text = text;
	}

	/** {@inheritDoc} */
	@Override
	public long getTimestamp()
	{
		return this.timestamp;
	}

	/** {@inheritDoc} */
	@Override
	public void setTimestamp(long timestamp)
	{
		this.timestamp = timestamp;
	}

	/** {@inheritDoc} */
	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		result = result * PRIME + java.util.Arrays.hashCode(this.getHash());
		result = result * PRIME + java.util.Arrays.hashCode(this.getSenderHash());
		result = result * PRIME + java.util.Arrays.hashCode(this.getSignature());
		final Object $text = this.getText();
		result = result * PRIME + ($text == null ? 43 : $text.hashCode());
		final long $timestamp = this.getTimestamp();
		result = result * PRIME + (int)($timestamp >>> 32 ^ $timestamp);
		return result;
	}
}
