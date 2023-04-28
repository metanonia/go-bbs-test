package bbs_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/require"
)

func TestBbsSign(t *testing.T) {
	// Key Generation
	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	bls := bbs12381g2pub.New()

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}

	signatureBytes, err := bls.SignWithKey(messagesBytes, privKey)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)
	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	// invalid private key bytes
	signatureBytes2, err := bls.Sign(messagesBytes, []byte("invalid"))
	require.Error(t, err)
	require.EqualError(t, err, "unmarshal private key: invalid size of private key")
	require.Nil(t, signatureBytes2)

	// at least one message must be passed
	signatureBytes2, err = bls.Sign([][]byte{}, privKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "messages are not defined")
	require.Nil(t, signatureBytes2)
	// Verify
	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	// Generate Proof
	nonce := []byte("nonce")
	revealedIndexes := []int{0, 2}
	proofBytes, err := bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
	require.NoError(t, err)
	require.NotEmpty(t, proofBytes)

	// Make RevealedMessage
	revealedMessages := make([][]byte, len(revealedIndexes))
	for i, ind := range revealedIndexes {
		revealedMessages[i] = messagesBytes[ind]
	}

	// VerifyProof
	require.NoError(t, bls.VerifyProof(revealedMessages, proofBytes, nonce, pubKeyBytes))

	revealedIndexes2 := []int{0, 2, 4, 7, 9, 11}
		_, err = bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes2)
	require.EqualError(t, err, "init proof of knowledge signature: invalid size: 6 revealed indexes is larger than 4 messages")

	wrongProofBytes, errDecode := base64.StdEncoding.DecodeString(`AAwP/4nFun/RtaXtUVTppUimMRTcEROs3gbjh9iqjGQAsvD+ne2uzME26gY4zNBcMKpvyLD4I6UGm8ATKLQI4OUiBXHNCQZI4YEM5hWI7AzhFXLEEVDFL0Gzr4S04PvcJsmV74BqST8iI1HUO2TCjdT1LkhgPabP/Zy8IpnbWUtLZO1t76NFwCV8+R1YpOozTNKRQQAAAHSpyGry6Rx3PRuOZUeqk4iGFq67iHSiBybjo6muud7aUyCxd9AW3onTlV2Nxz8AJD0AAAACB3FmuAUcklAj5cdSdw7VY57y7p4VmfPCKaEp1SSJTJRZXiE2xUqDntend+tkq+jjHhLCk56zk5GoZzr280IeuLne4WgpB2kNN7n5dqRpy4+UkS5+kiorLtKiJuWhk+OFTiB8jFlTbm0dH3O3tm5CzQAAAAIhY6I8vQ96tdSoyGy09wEMCdWzB06GElVHeQhWVw8fukq1dUAwWRXmZKT8kxDNAlp2NS7fXpEGXZ9fF7+c1IJp`)
	require.NoError(t, errDecode)
	err = bls.VerifyProof(revealedMessages, wrongProofBytes, nonce, pubKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "payload revealed bigger from messages")

	err = bls.VerifyProof(revealedMessages, []byte("?"), nonce, pubKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "parse signature proof: invalid size of PoK payload")

	proofBytesCopy := make([]byte, 5)
	copy(proofBytesCopy, proofBytes)
	err = bls.VerifyProof(revealedMessages, proofBytesCopy, nonce, pubKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "parse signature proof: invalid size of signature proof")

	proofBytesCopy = make([]byte, len(proofBytes))
	copy(proofBytesCopy, proofBytes)
	proofBytesCopy[21] = 255 - proofBytesCopy[21]
	err = bls.VerifyProof(revealedMessages, proofBytesCopy, nonce, pubKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "parse signature proof: parse G1 point: point is not on curve")

	err = bls.VerifyProof(revealedMessages, proofBytes, nonce, []byte("invalid public key"))
	require.Error(t, err)
	require.EqualError(t, err, "parse public key: invalid size of public key")


}