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

import iaik.utils.SmtpException;
import iaik.utils.SmtpMailer;

/**
 * A simple SMPT mailer demo programm.
 * @version File Revision <!-- $$Revision: --> 10 <!-- $ -->
 */
public class SmtpMail {

	public static void main(String argv[]) {

		String lineSeparator = System.getProperty("line.separator");

		SmtpMailer mailer = new SmtpMailer("mailhost");

		mailer.setFrom("Test", "smimetest@iaik.tugraz.at");
		mailer.addTo("Bill Gates", "smimetest@iaik.tugraz.at");

		mailer.setReplyTo("Test", "smimetest@iaik.tugraz.at");
		mailer.setSubject("SmtpMailer Test!");

		mailer
		    .addText("Hello JavaSecurity development team!" + lineSeparator + lineSeparator);
		mailer.addText("This EMail was created with your fantastic SMTP EMail tool."
		    + lineSeparator);
		mailer.addText(lineSeparator);
		mailer.addText("Ciao." + lineSeparator);

		try {
			boolean ok = mailer.sendMail();
			System.out.println("Response codes from server: " + (ok ? "OK" : "NOT OK"));
		} catch (SmtpException ex) {
			System.out.println("SmtpException: " + ex.getMessage());
		}
	}
}
