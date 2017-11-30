// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2015 Stiftung Secure Information and
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

package demo.pkcs.pkcs11.provider.utils;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.BasicOCSPResponse;
import iaik.x509.ocsp.CertStatus;
import iaik.x509.ocsp.OCSPException;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.Request;
import iaik.x509.ocsp.ResponderID;
import iaik.x509.ocsp.SingleResponse;
import iaik.x509.ocsp.UnknownInfo;
import iaik.x509.ocsp.extensions.ServiceLocator;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class CreateOCSPResponse {

  /**
   * Creates an ocsp response answering the given ocsp request.
   * 
   * @param is
   *          the encoded OCSP request supplied from an input stream
   * @param requestorKey
   *          the signing key of the requestor (may be supplied for allowing to verify a signed
   *          request with no certificates included)
   * @param includeExtensions
   *          if extensions shall be included
   * @return the DER encoded OCSPResponse
   */
  public static OCSPResponse createOCSPResponse(OCSPRequest ocspRequest,
      PublicKey requestorKey, X509Certificate[] responderCerts) {

    OCSPResponse ocspResponse = null;

    // first parse the request
    int responseStatus = OCSPResponse.successful;
    System.out.println("Parsing request...");

    try {
      if (ocspRequest.containsSignature()) {
        System.out.println("Request is signed.");

        boolean signatureOk = false;
        if (requestorKey != null) {
          System.out.println("Verifying signature using supplied requestor key.");
          try {
            ocspRequest.verify(requestorKey);
            signatureOk = true;
            System.out.println("Signature ok");

          } catch (Exception ex) {
          }
        }
        if (!signatureOk && ocspRequest.containsCertificates()) {
          System.out.println("Verifying signature with included signer cert...");

          X509Certificate signerCert = ocspRequest.verify();
          System.out.println("Signature ok from request signer "
              + signerCert.getSubjectDN());
          signatureOk = true;
        }
        if (!signatureOk) {
          System.out
              .println("Request signed but cannot verify signature since missing signer key. Sending malformed request!");
          responseStatus = OCSPResponse.malformedRequest;
        }
      } else {
        System.out.println("Unsigned request!");
      }

    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Cannot verify; sending internalError: " + ex.getMessage());
      responseStatus = OCSPResponse.internalError;
    } catch (OCSPException ex) {
      System.out
          .println("Included certs do not belong to signer; sending malformedRequest : "
              + ex.getMessage());
      responseStatus = OCSPResponse.malformedRequest;
    } catch (InvalidKeyException ex) {
      System.out.println("Signer key invalid; sending malformedRequest : "
          + ex.getMessage());
      responseStatus = OCSPResponse.malformedRequest;
    } catch (SignatureException ex) {
      System.out.println("Signature verification error; sending malformedRequest : "
          + ex.getMessage());
      responseStatus = OCSPResponse.malformedRequest;
    } catch (Exception ex) {
      ex.printStackTrace();
      System.out
          .println("Some error occured during request parsing/verification; sending tryLater "
              + ex.getMessage());
      responseStatus = OCSPResponse.tryLater;
    }
    if (responseStatus != OCSPResponse.successful) {
      return new OCSPResponse(responseStatus);
    }

    try {
      // does client understand Basic OCSP response type?
      ObjectID[] accepatablResponseTypes = ocspRequest.getAccepatableResponseTypes();
      if ((accepatablResponseTypes != null) && (accepatablResponseTypes.length > 0)) {
        boolean supportsBasic = false;
        for (int i = 0; i < accepatablResponseTypes.length; i++) {
          if (accepatablResponseTypes[i].equals(BasicOCSPResponse.responseType)) {
            supportsBasic = true;
            break;
          }
        }
        if (!supportsBasic) {
          // what to do if client does not support basic OCSP response type??
          // we send an basic response anyway, since there seems to be no proper status message
          System.out
              .println("Warning! Client does not support basic response type. Using it anyway...");
        }
      }
    } catch (Exception ex) {
      // ignore this
    }
    // successfull
    ocspResponse = new OCSPResponse(OCSPResponse.successful);
    // now we build the basic ocsp response
    BasicOCSPResponse basicOCSPResponse = new BasicOCSPResponse();

    try {
      // responder ID
      ResponderID responderID = new ResponderID((Name) responderCerts[0].getSubjectDN());
      basicOCSPResponse.setResponderID(responderID);

      GregorianCalendar date = new GregorianCalendar();
      // producedAt date
      Date producedAt = date.getTime();
      basicOCSPResponse.setProducedAt(producedAt);

      // thisUpdate date
      Date thisUpdate = date.getTime();
      // nextUpdate date
      date.add(Calendar.MONTH, 1);
      Date nextUpdate = date.getTime();
      // archiveCutoff
      date.add(Calendar.YEAR, -3);

      // create the single responses for requests included
      Request[] requests = ocspRequest.getRequestList();
      SingleResponse[] singleResponses = new SingleResponse[requests.length];

      for (int i = 0; i < requests.length; i++) {
        Request request = requests[i];
        CertStatus certStatus = null;
        // check the service locator
        ServiceLocator serviceLocator = request.getServiceLocator();
        if (serviceLocator != null) {
          System.out.println("Request No. " + i
              + " contains the ServiceLocator extension:");
          System.out.println(serviceLocator + "\n");

          Name issuer = serviceLocator.getIssuer();
          if (!issuer.equals(responderCerts[0].getSubjectDN())) {
            // client does not trust our responder; but we are not able to forward it
            // --> CertStatus unknown
            certStatus = new CertStatus(new UnknownInfo());
          }
        }
        if (certStatus == null) {
          // here now the server checks the status of the cert
          // we only can give information about one cert
          // we assume "good" here
          certStatus = new CertStatus();
        }
        singleResponses[i] = new SingleResponse(request.getReqCert(), certStatus,
            thisUpdate);
        singleResponses[i].setNextUpdate(nextUpdate);

      }
      // set the single responses
      basicOCSPResponse.setSingleResponses(singleResponses);

    } catch (Exception ex) {
      ex.printStackTrace();

      System.out.println("Some error occured; sending tryLater " + ex.getMessage());
      return new OCSPResponse(OCSPResponse.tryLater);

    }

    basicOCSPResponse.setCertificates(new X509Certificate[] { responderCerts[0] });

    ocspResponse.setResponse(basicOCSPResponse);
    return ocspResponse;

  }

}
