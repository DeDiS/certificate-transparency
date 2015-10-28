package main

import (
	"encoding/base64"
	"encoding/hex"
	dbg "github.com/dedis/cothority/lib/debug_lvl"
	"io/ioutil"
	"testing"
	"github.com/dedis/cothority/lib/conode"
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

	if conode.VerifySignature(suite, reply, public, sthHashByte) {
		dbg.Print("Yay - passing all tests")
	} else {
		dbg.Fatal("Oups - some more work to do")
	}
}
