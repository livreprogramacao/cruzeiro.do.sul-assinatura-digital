// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2013 Stiftung Secure Information and
//                           Communication Technologies SIC
// http://www.sic.st
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

package demo;

import iaik.utils.CriticalObject;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.IOException;
import java.io.Serializable;

import demo.util.DemoUtil;

/**
 * This class demonstrates the usage of class CriticalData.
 * @version File Revision <!-- $$Revision: --> 16 <!-- $ -->
 */
public class CriticalObjectDemo implements Serializable {

	private static final long serialVersionUID = 821410039420572922L;

	byte[] data; // the critical data within this object
	int x; // the critical data within this object

	/**
	 * A default constructor which initializes the variables.
	 */
	public CriticalObjectDemo() {
		data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		x = 190;
	}

	/**
	 * This method is called from class CriticalObject after encrypting the content
	 * and it is responsible for destroying all its critical data. This demo for
	 * example first sets the content of the byte array to zero and then sets the
	 * reference to it to <code>null</code>. Another variable x is also set to 0.
	 */
	public void destroyCriticalData() {
		CryptoUtils.zeroBlock(data);
		data = null;
		x = 0;
	}

	/**
	 * Returns a string that represents the content of this object.
	 */
	public String toString() {
		StringBuffer buf = new StringBuffer();
		if (data == null) buf.append("array: empty\n");
		else buf.append("array: " + Util.toString(data) + "\n");
		buf.append("x: " + x);
		return buf.toString();
	}

	public static void start() {
		try {
			// create a new demo object
			CriticalObjectDemo obj = new CriticalObjectDemo();
			// and show it's contents
			System.out.println(obj);
			// a temp key
			byte[] key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
			// now secure our demo object
			CriticalObject test = new CriticalObject(obj, key);
			// show that now the object is empty
			System.out.println(obj);
			// and retrive the demo object
			CriticalObjectDemo new_obj = (CriticalObjectDemo) test.getObject(key);
			// everything shall be back again
			System.out.println(new_obj);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * The main method of the demo.
	 * First a new CriticalObjectDemo object is created and secured through
	 * a CriticalObject using the specified key.<p>
	 * Then the object is retrieved using the same key.
	 */
	public static void main(String[] argv)
	    throws IOException
	{

		DemoUtil.initDemos();
		start();
		System.in.read();
	}
}
