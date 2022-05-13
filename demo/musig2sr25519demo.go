package main

import (
	"log"

	musig2sr25519 "github.com/chainx-org/musig2-sr25519-go-api/musig2-sr25519"
)

func main() {
	log.SetFlags(log.Llongfile | log.Lmicroseconds | log.Ldate)
	log.SetPrefix("[Musig2Sr25519]")
	phrase1 := "flame flock chunk trim modify raise rough client coin busy income smile"
	phrase2 := "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
	phrase3 := "awesome beef hill broccoli strike poem rebel unique turn circle cool system"

	var msg uint32 = 666666

	privateA, error := musig2sr25519.GetMyPrivkey(phrase1)
	if error != nil {
		log.Fatal(error)
	}
	privateB, error := musig2sr25519.GetMyPrivkey(phrase2)
	if error != nil {
		log.Fatal(error)
	}
	privateC, error := musig2sr25519.GetMyPrivkey(phrase3)
	if error != nil {
		log.Fatal(error)
	}

	publicA, error := musig2sr25519.GetMyPubkey(privateA)
	if error != nil {
		log.Fatal(error)
	}
	publicB, error := musig2sr25519.GetMyPubkey(privateB)
	if error != nil {
		log.Fatal(error)
	}
	publicC, error := musig2sr25519.GetMyPubkey(privateC)
	if error != nil {
		log.Fatal(error)
	}

	round1StateA := musig2sr25519.GetRound1State()
	round1StateB := musig2sr25519.GetRound1State()
	round1StateC := musig2sr25519.GetRound1State()

	encodedRound1StateA := musig2sr25519.EncodeRound1State(round1StateA)
	round1StateA = musig2sr25519.DecodeRound1State(encodedRound1StateA)

	round1MsgA, error := musig2sr25519.GetRound1Msg(round1StateA)
	if error != nil {
		log.Fatal(error)
	}
	round1MsgB, error := musig2sr25519.GetRound1Msg(round1StateB)
	if error != nil {
		log.Fatal(error)
	}
	round1MsgC, error := musig2sr25519.GetRound1Msg(round1StateC)
	if error != nil {
		log.Fatal(error)
	}

	pubkeys := []string{publicA, publicB, publicC}

	round2MsgA, error := musig2sr25519.GetRound2Msg(round1StateA, msg, privateA, pubkeys, []string{round1MsgB, round1MsgC})
	if error != nil {
		log.Fatal(error)
	}

	round2MsgB, error := musig2sr25519.GetRound2Msg(round1StateB, msg, privateB, pubkeys, []string{round1MsgA, round1MsgC})
	if error != nil {
		log.Fatal(error)
	}

	round2MsgC, error := musig2sr25519.GetRound2Msg(round1StateC, msg, privateC, pubkeys, []string{round1MsgA, round1MsgB})
	if error != nil {
		log.Fatal(error)
	}

	sig, error := musig2sr25519.GetAggSignature([]string{round2MsgA, round2MsgB, round2MsgC})
	if error != nil {
		log.Fatal(error)
	}
	log.Println("sig:", sig)

	aggPubkey, error := musig2sr25519.GetAggPublicKey(pubkeys)
	if error != nil {
		log.Fatal(error)
	}
	log.Println("aggPubkey:", aggPubkey)

	pubkeyAB, error := musig2sr25519.GetAggPublicKey([]string{publicA, publicB})
	if error != nil {
		log.Fatal(error)
	}

	thresholdPubkey, error := musig2sr25519.GenerateThresholdPubkey(pubkeys, 2)
	if error != nil {
		log.Fatal(error)
	}
	log.Println("thresholdPubkey:", thresholdPubkey)

	control, error := musig2sr25519.GenerateControlBlock(pubkeys, 2, pubkeyAB)
	if error != nil {
		log.Fatal(error)
	}
	log.Println("control:", control)
}
