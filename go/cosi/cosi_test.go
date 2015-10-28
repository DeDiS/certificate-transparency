package main

import (
	"encoding/base64"
	"encoding/hex"
	dbg "github.com/dedis/cothority/lib/debug_lvl"
	"io/ioutil"
	"testing"
)

func TestReadConf(t *testing.T) {
	ReadConf()

	dbg.Printf("%+v\n", conf)
	dbg.Printf("Public key: %+v", public)
}

func TestReadSha(t *testing.T) {
	sthHash, _ := ioutil.ReadFile("test_sth_sha256.json")
	dbg.Print("Hash:", sthHash)
	sthHashByte, err := base64.StdEncoding.DecodeString(string(sthHash))
	if err != nil {
		dbg.Fatal("Couldn't convert", sthHash, "from base64")
	}
	dbg.Print("HashByte:", sthHashByte)
	sthHashHex := hex.EncodeToString(sthHashByte)
	dbg.Print("HashHex:", sthHashHex)
}

func TestJSONtoSignature(t *testing.T) {
	str, err := ioutil.ReadFile("test_sth_cosi.json")
	dbg.DebugVisible = 5
	SetSuite("ed25519")

	reply, err := JSONtoSignature(string(str))
	dbg.Printf("Reply is: %+v - %s\n", reply, err)

	ReadConf()
	if reply.SigBroad.X0_hat.Equal(public) {
		dbg.Lvl2("X0 verified")
	} else {
		dbg.Fatal("X0 couldn't be verfied")
	}
}

func TestVerify(t *testing.T) {
	ReadConf()
	str, _ := ioutil.ReadFile("test_sth_cosi.json")
	reply, err := JSONtoSignature(string(str))
	if err != nil {
		dbg.Fatal("Couldn't read json from ", str)
	}

	sthHash, err := ioutil.ReadFile("test_sth_sha256.json")
	if err != nil {
		dbg.Fatal("Couldn't read sha256-hash")
	}
	sthHashByte, err := base64.StdEncoding.DecodeString(string(sthHash))
	if err != nil {
		dbg.Fatal("Couldn't convert", sthHash, "from base64")
	}
	dbg.Print("HashByte:", sthHashByte)

	if verifySignature(sthHashByte, reply) {
		dbg.Print("Yay - passing all tests")
	} else {
		dbg.Fatal("Oups - some more work to do")
	}
}

/*
func TestVerify(t *testing.T) {
	ReadConf()
	str, _ := ioutil.ReadFile("test_sth_cosi.json")
	reply, err := JSONtoSignature(string(str))
	if err != nil {
		dbg.Fatal("Couldn't read json from ", str)
	}

	err = verifyChallenge(suite, reply)
	if err != nil {
		dbg.Fatal("Couldn't check the challenge")
	} else {
		dbg.Lvl1("Challenge is OK")
	}

	sig := defs.BasicSignature{
		Chall: reply.SigBroad.C,
		Resp:  reply.SigBroad.R0_hat,
	}

	sthHash, err := ioutil.ReadFile("test_sth_sha256.json")
	if err != nil {
		dbg.Fatal("Couldn't read sha256-hash")
	}
	sthHashByte, err := base64.StdEncoding.DecodeString(string(sthHash))
	if err != nil {
		dbg.Fatal("Couldn't convert", sthHash, "from base64")
	}
	dbg.Print("HashByte:", sthHashByte)
	//sthHashHex := hex.EncodeToString(sthHashByte);

	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, reply.Timestamp); err != nil {
		dbg.Lvl1("Error marshaling the timestamp for signature verification")
	}
	msg := append(b.Bytes(), []byte(reply.MerkleRoot)...)
	err = SchnorrVerify(suite, []byte(sthHashByte), public, sig)
	//err = SchnorrVerify(suite, []byte("test"), public, sig)
	if err != nil {
		dbg.Fatal("Couldn't verify Schnorr")
	}
	return
}
*/
