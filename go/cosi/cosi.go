package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"io/ioutil"

	"github.com/dedis/cothority/app/conode/defs"
	"github.com/dedis/cothority/lib/app"
	"github.com/dedis/cothority/lib/cliutils"
	dbg "github.com/dedis/cothority/lib/debug_lvl"
	"github.com/dedis/cothority/lib/hashid"
	"github.com/dedis/cothority/lib/proof"
	"github.com/dedis/crypto/abstract"
	"github.com/google/certificate-transparency/go/client"
)

var logUri = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var dump = flag.Bool("dump", false, "Dump request to uri")

var public abstract.Point

func main() {
	ReadConf()
	logClient := client.New(*logUri)
	STH, err := logClient.GetSTH()
	if err != nil {
		dbg.Fatal("Couldn't get STH:", err)
	}
	dbg.Printf("STH is %+v", STH)

	if *dump {
		ioutil.WriteFile("test_sth_cosi.json", []byte(STH.CosiSignature), 0660)
		ioutil.WriteFile("test_sth_sha256.json",
			[]byte(STH.SHA256RootHash.Base64String()), 0660)
	} else {
		sig, err := JSONtoSignature(STH.CosiSignature)
		dbg.Printf("signature is %+v - error: &s\n", sig, err)
		//VerifySignature(c.Args().First(), c.String("sig"))
	}
}

func SetSuite(suiteStr string) {
	suite = app.GetSuite(suiteStr)
}

func ReadConf() {
	flag.Parse()

	conf = new(app.ConfigConode)
	err := app.ReadTomlConfig(conf, "config.toml")
	if err != nil {
		dbg.Fatal("Couldn't load config-fiel")
	}
	SetSuite(conf.Suite)
	public, _ = cliutils.ReadPub64(suite, strings.NewReader(conf.AggPubKey))
}

// Our crypto-suite used in the program
var suite abstract.Suite

// the configuration file of the cothority tree used
var conf *app.ConfigConode

// Verifies that the 'message' is included in the signature and that it
// is correct.
// Message is your own hash, and reply contains the inclusion proof + signature
// on the aggregated message
func verifySignature(message hashid.HashId, reply *defs.StampReply) bool {
	// First check if the challenge is ok
	if err := verifyChallenge(suite, reply); err != nil {
		dbg.Lvl1("Challenge-check : FAILED (", err, ")")
		return false
	}
	dbg.Lvl1("Challenge-check : OK")
	// Then check if the signature is ok
	sig := defs.BasicSignature{
		Chall: reply.SigBroad.C,
		Resp:  reply.SigBroad.R0_hat,
	}
	public, _ := cliutils.ReadPub64(suite, strings.NewReader(conf.AggPubKey))
	// Incorporate the timestamp in the message since the verification process
	// is done by reconstructing the challenge
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, reply.Timestamp); err != nil {
		dbg.Lvl1("Error marshaling the timestamp for signature verification")
	}
	msg := append(b.Bytes(), []byte(reply.MerkleRoot)...)
	if err := SchnorrVerify(suite, msg, public, sig); err != nil {
		dbg.Lvl1("Signature-check : FAILED (", err, ")")
		return false
	}
	dbg.Lvl1("Signature-check : OK")

	// finally check the proof
	if !proof.CheckProof(suite.Hash, reply.MerkleRoot, hashid.HashId(message), reply.Prf) {
		dbg.Lvl1("Inclusion-check : FAILED")
		return false
	}
	dbg.Lvl1("Inclusion-check : OK")
	return true
}

// verifyChallenge will recontstruct the challenge in order to see if any of the
// components of the challenge has been spoofed or not. It may be a different
// timestamp .
func verifyChallenge(suite abstract.Suite, reply *defs.StampReply) error {

	// marshal the V
	pbuf, err := reply.SigBroad.V0_hat.MarshalBinary()
	if err != nil {
		return err
	}
	c := suite.Cipher(pbuf)
	// concat timestamp and merkle root
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, reply.Timestamp); err != nil {
		return err
	}
	cbuf := append(b.Bytes(), reply.MerkleRoot...)
	c.Message(nil, nil, cbuf)
	challenge := suite.Secret().Pick(c)
	if challenge.Equal(reply.SigBroad.C) {
		return nil
	}
	return errors.New("Challenge reconstructed is not equal to the one given ><")
}

// A simple verification of a schnorr signature given the message
//TAKEN FROM SIG_TEST from abstract
func SchnorrVerify(suite abstract.Suite, message []byte, publicKey abstract.Point, sig defs.BasicSignature) error {
	r := sig.Resp
	c := sig.Chall

	// Check that: base**r_hat * X_hat**c == V_hat
	// Equivalent to base**(r+xc) == base**(v) == T in vanillaElGamal
	Aux := suite.Point()
	V_clean := suite.Point()
	V_clean.Add(V_clean.Mul(nil, r), Aux.Mul(publicKey, c))
	// T is the recreated V_hat
	T := suite.Point().Null()
	T.Add(T, V_clean)

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	// copy of hashSchnorr
	bufPoint, _ := T.MarshalBinary()
	cipher := suite.Cipher(bufPoint)
	cipher.Message(nil, nil, message)
	hash := suite.Secret().Pick(cipher)
	if !hash.Equal(sig.Chall) {
		return errors.New("invalid signature")
	}
	return nil
}

// Decodes the JSON coming from the CT-server and puts back in a 'StampReply'-structure
func JSONtoSignature(sigStr string) (*defs.StampReply, error) {
	tsm := &defs.TimeStampMessage{}
	err := json.Unmarshal([]byte(sigStr), &tsm)
	if err != nil {
		dbg.Lvl2("Couldn't unmarshal ", sigStr)
		return nil, err
	}

	return tsm.Srep, err
}

// Takes a file to be hashed - reads in chunks of 1MB
func hashFile(name string) []byte {
	hash := suite.Hash()
	file, err := os.Open(name)
	if err != nil {
		dbg.Fatal("Couldn't open file", name)
	}

	buflen := 1024 * 1024
	buf := make([]byte, buflen)
	read := buflen
	for read == buflen {
		read, err = file.Read(buf)
		if err != nil && err != io.EOF {
			dbg.Fatal("Error while reading bytes")
		}
		hash.Write(buf)
	}
	return hash.Sum(nil)
}
