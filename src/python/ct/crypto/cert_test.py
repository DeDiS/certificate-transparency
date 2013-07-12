#!/usr/bin/env python

import gflags
import unittest
import sys
from ct.crypto import cert, error

FLAGS = gflags.FLAGS
gflags.DEFINE_string('testdata_dir', "ct/crypto/testdata",
                     "Location of test certs")

class CertificateTest(unittest.TestCase):
    _PEM_FILE = "google_cert.pem"
    # Contains 3 certificates
    # C=US/ST=California/L=Mountain View/O=Google Inc/CN=www.google.com
    # C=US/O=Google Inc/CN=Google Internet Authority
    # C=US/O=Equifax/OU=Equifax Secure Certificate Authority

    _PEM_CHAIN_FILE = "google_chain.pem"
    _DER_FILE = "google_cert.der"

    @property
    def pem_file(self):
        return FLAGS.testdata_dir + "/" + self._PEM_FILE

    @property
    def der_file(self):
        return FLAGS.testdata_dir + "/" + self._DER_FILE

    @property
    def chain_file(self):
        return FLAGS.testdata_dir + "/" + self._PEM_CHAIN_FILE

    def test_from_pem_file(self):
        c = cert.Certificate.from_pem_file(self.pem_file)
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_certs_from_pem_file(self):
        certs = [c for c in cert.certs_from_pem_file(self.chain_file)]
        self.assertEqual(3, len(certs))
        self.assertTrue(all(map(lambda x: isinstance(x, cert.Certificate),
                                certs)))
        self.assertTrue("google.com" in certs[0].subject_name())
        self.assertTrue("Google Inc" in certs[1].subject_name())
        self.assertTrue("Equifax" in certs[2].subject_name())

    def test_from_pem(self):
        with open(self.pem_file) as f:
            c = cert.Certificate.from_pem(f.read())
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_all_from_pem(self):
        with open(self.chain_file) as f:
            certs = [c for c in cert.certs_from_pem(f.read())]
        self.assertEqual(3, len(certs))
        self.assertTrue(all(map(lambda x: isinstance(x, cert.Certificate),
                                certs)))
        self.assertTrue("google.com" in certs[0].subject_name())
        self.assertTrue("Google Inc" in certs[1].subject_name())
        self.assertTrue("Equifax" in certs[2].subject_name())

    def test_from_der_file(self):
        c = cert.Certificate.from_der_file(self.der_file)
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_from_der(self):
        with open(self.der_file, 'rb') as f:
            c = cert.Certificate.from_der(f.read())
        self.assertTrue(isinstance(c, cert.Certificate))

    def test_invalid_encoding_raises(self):
        self.assertRaises(error.EncodingError, cert.Certificate.from_der,
                          "bogus_der_string")
        self.assertRaises(error.EncodingError, cert.Certificate.from_pem,
                          "bogus_pem_string")

    def test_to_der(self):
        with open(self.der_file, 'rb') as f:
            der_string = f.read()
        c = cert.Certificate(der_string)
        self.assertEqual(der_string, c.to_der())

    def test_subject_name(self):
        c = cert.Certificate.from_der_file(self.der_file)
        subject = c.subject_name()
        # C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com
        self.assertTrue("US" in subject)
        self.assertTrue("California" in subject)
        self.assertTrue("Mountain View" in subject)
        self.assertTrue("Google Inc" in subject)
        self.assertTrue("*.google.com" in subject)

    def test_issuer_name(self):
        c = cert.Certificate.from_der_file(self.der_file)
        issuer = c.issuer_name()
        # Issuer: C=US, O=Google Inc, CN=Google Internet Authority
        self.assertTrue("US" in issuer)
        self.assertTrue("Google Inc" in issuer)
        self.assertTrue("Google Internet Authority" in issuer)

    def test_subject_common_name(self):
        c = cert.Certificate.from_der_file(self.der_file)
        self.assertEqual("*.google.com", c.subject_common_name())

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    unittest.main()
