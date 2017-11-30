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

package demo.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Event;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Label;
import java.awt.Point;
import java.math.BigInteger;
import java.security.SecureRandom;

import iaik.security.random.AWT10SeedGenerator;
import iaik.security.random.MetaSeedGenerator;
import iaik.security.random.SecRandom;
import iaik.security.random.SeedGenListener;
import iaik.security.random.SeedGenerator;

/**
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class RandomDemoAWT10 extends Frame implements SeedGenListener {
	private static final long serialVersionUID = -2112674879667983109L;

	AWT10SeedGenerator seedGen;

	public RandomDemoAWT10() {
		//{{INIT_CONTROLS
		setLayout(null);
		setVisible(false);
		setSize(430, 280);
		button1 = new java.awt.Button();
		button1.setLabel("New Seed");
		button1.setBounds(324, 120, 84, 24);
		button1.setBackground(new Color(12632256));
		add(button1);
		textArea1 = new java.awt.TextArea();
		textArea1.setBounds(24, 120, 288, 108);
		add(textArea1);
		statusLabel = new java.awt.Label("");
		statusLabel.setBounds(24, 240, 384, 24);
		add(statusLabel);
		label1 = new java.awt.Label("Random Number Generation Demo (AWT 1.0)", Label.CENTER);
		label1.setBounds(24, 12, 384, 24);
		label1.setFont(new Font("Dialog", Font.BOLD, 14));
		add(label1);
		label2 = new java.awt.Label(
		    "Please generate events by moving the mouse or typing in the");
		label2.setBounds(24, 60, 384, 24);
		add(label2);
		label3 = new java.awt.Label("textarea below.");
		label3.setBounds(24, 84, 384, 24);
		add(label3);
		button2 = new java.awt.Button();
		button2.setLabel("Quit");
		button2.setBounds(324, 192, 84, 24);
		button2.setBackground(new Color(12632256));
		add(button2);
		button3 = new java.awt.Button();
		button3.setLabel("New Random");
		button3.setBounds(324, 156, 84, 24);
		button3.setBackground(new Color(12632256));
		add(button3);
		setTitle("Random Number Generation Demo (AWT 1.0)");
		setResizable(false);
		//}}
		//{{INIT_MENUS
		//}}

		initSeedGen();
	}

	private boolean seedGenActive = false;
	private boolean seedAvailable = false;

	void initSeedGen() {
		seedGen = new AWT10SeedGenerator();
		seedGenActive = true;
		seedGen.setSeedGenListener(this);
		showStatus("Seed generation started.");
	}

	void finishSeedGen() {
		MetaSeedGenerator.setSeed(seedGen.getSeed());
		SeedGenerator.setDefault(MetaSeedGenerator.class);
		seedGenActive = false;
		seedAvailable = true;
	}

	private void newRandom() {
		if (!seedAvailable) {
			showStatus("No seed generated so far.");
			return;
		}
		byte[] rBytes = new byte[15];
		SecureRandom sRand = SecRandom.getDefault();
		sRand.nextBytes(rBytes);
		textArea1.append("\n" + new BigInteger(1, rBytes).toString());
		showStatus("Random number generated.");
	}

	public void bitsGenerated(int bitsReady, int bitsTotal) {
		if (bitsReady == bitsTotal) {
			showStatus("Seed generation completed.");
			finishSeedGen();
		} else {
			showStatus(bitsReady + " seed bits of " + bitsTotal + " generated");
		}
	}

	void showStatus(String text) {
		statusLabel.setText("Status: " + text);
	}

	public boolean handleEvent(Event evt) {
		// if the SeedGenerator is active, pass the event to it first
		if (seedGenActive) {
			switch (evt.id) { // check if the event is of a type we care about
			case Event.MOUSE_MOVE:
			case Event.MOUSE_DRAG:
			case Event.MOUSE_DOWN:
			case Event.ACTION_EVENT:
			case Event.KEY_PRESS:
			case Event.KEY_ACTION:
				seedGen.addSeedObject(evt);
				break;

			default:
				// ignore the event
			}
		}
		// rest of normal event handling follows
		if ((evt.target == this) && (evt.id == Event.WINDOW_DESTROY)) {
			Frame1_WindowClosing();
		}
		if ((evt.target == button1) && (evt.id == Event.ACTION_EVENT)) {
			button1_ActionPerformed();
		}
		if ((evt.target == button2) && (evt.id == Event.ACTION_EVENT)) {
			button2_ActionPerformed();
		}
		if ((evt.target == button3) && (evt.id == Event.ACTION_EVENT)) {
			button3_ActionPerformed();
		}
		return false;
	}

	public RandomDemoAWT10(String title) {
		this();
		setTitle(title);
	}

	public void setVisible(boolean b) {
		if (b) {
			setLocation(50, 50);
		}
		super.setVisible(b);
	}

	static public void main(String args[]) {
		(new RandomDemoAWT10()).setVisible(true);
	}

	public void addNotify() {
		// Record the size of the window prior to calling parents addNotify.
		Dimension d = getSize();

		super.addNotify();

		if (fComponentsAdjusted) return;

		// Adjust components according to the insets
		setSize(getInsets().left + getInsets().right + d.width, getInsets().top
		    + getInsets().bottom + d.height);
		Component components[] = getComponents();
		for (int i = 0; i < components.length; i++) {
			Point p = components[i].getLocation();
			p.translate(getInsets().left, getInsets().top);
			components[i].setLocation(p);
		}
		fComponentsAdjusted = true;
	}

	// Used for addNotify check.
	boolean fComponentsAdjusted = false;

	//{{DECLARE_CONTROLS
	java.awt.Button button1;
	java.awt.TextArea textArea1;
	java.awt.Label statusLabel;
	java.awt.Label label1;
	java.awt.Label label2;
	java.awt.Label label3;
	java.awt.Button button2;
	java.awt.Button button3;

	//}}

	//{{DECLARE_MENUS
	//}}

	void Frame1_WindowClosing() {
		setVisible(false); // hide the Frame
		System.exit(0);
	}

	void button1_ActionPerformed() {
		initSeedGen();
	}

	void button2_ActionPerformed() {
		System.exit(0);
	}

	void button3_ActionPerformed() {
		newRandom();
	}
}
