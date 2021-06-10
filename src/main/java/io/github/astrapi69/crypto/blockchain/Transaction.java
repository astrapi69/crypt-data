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
package io.github.astrapi69.crypto.blockchain;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.blockchain.api.ITransaction;
import io.github.astrapi69.crypto.hash.HashExtensions;

/**
 * The class {@link Transaction}
 */
public class Transaction implements ITransaction
{

	private byte[] hash;

	private byte[] senderHash;

	private byte[] signature;

	private String text;

	private long timestamp;

	public Transaction()
	{
	}

	public Transaction(String text, byte[] senderHash, byte[] signature)
	{
		this.text = text;
		this.senderHash = senderHash;
		this.signature = signature;
		this.timestamp = System.currentTimeMillis();
		this.hash = HashExtensions.hash(text.getBytes(), senderHash, signature, timestamp,
			HashAlgorithm.SHA256);
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof Transaction;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Transaction))
			return false;
		final Transaction other = (Transaction)o;
		if (!other.canEqual(this))
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
		if (this.getTimestamp() != other.getTimestamp())
			return false;
		return true;
	}

	@Override
	public byte[] getHash()
	{
		return this.hash;
	}

	@Override
	public byte[] getSenderHash()
	{
		return this.senderHash;
	}

	@Override
	public byte[] getSignableData()
	{
		return text.getBytes();
	}

	@Override
	public byte[] getSignature()
	{
		return this.signature;
	}

	@Override
	public String getText()
	{
		return this.text;
	}

	@Override
	public long getTimestamp()
	{
		return this.timestamp;
	}

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

	@Override
	public void setHash(byte[] hash)
	{
		this.hash = hash;
	}

	@Override
	public void setSenderHash(byte[] senderHash)
	{
		this.senderHash = senderHash;
	}

	@Override
	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}

	@Override
	public void setText(String text)
	{
		this.text = text;
	}

	@Override
	public void setTimestamp(long timestamp)
	{
		this.timestamp = timestamp;
	}
}
