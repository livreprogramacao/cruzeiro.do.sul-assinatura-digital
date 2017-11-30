IAIK [CP]AdES toolkit
=============================

This package contains the IAIK [CP]AdES toolkit.
It allows the creation of signed PDFs using
the PAdES signature specification.
The toolkit either needs the iText-library (http://itextpdf.com/)
or the PDFBox-library (http://pdfbox.apache.org)
for the manipulation of the PDF structure, but uses
other IAIK toolkits for the cryptographic operations.
The following IAIK toolkits are required, in order to use
the IAIK [CP]AdES toolkit:
* IAIK JCE
* IAIK CMS
* IAIK TSP (for timestamps)

You possibly also need the PKCS#11 Provider, if you want to
use a PKCS#11 token to sign the PDF.

The current version of this package is available from

http://jce.iaik.tugraz.at/download/

After downloading the toolkit package use your favorite 
browser to view the doc/index.html for further information.


Your SIC/IAIK JavaSecurity Team
