package bbs_test

import (
	"crypto/sha256"
	"github.com/stretchr/testify/require"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"testing"
)

func TestSign(t *testing.T) {
	// 서명자 키 생성..
	_, issuerPrivateKey, err := bbs.GenerateKeyPair(sha256.New, nil)
	if err != nil {
		panic(err)
	}
	/*
		issuerPrivateKeyBytes, err := hex.DecodeString("4b47459199b0c2210de9d28c1412551c28c57caae60872aa677bc9af2038d22b")
		require.NoError(t, err)

		issuerPrivateKey, err := bbs.UnmarshalPrivateKey(issuerPrivateKeyBytes)
		require.NoError(t, err)
	*/

	// 서명자는 본인의 공개키를 이용하여, issuerGenerators 및 nonce를 생성하여, holder에게 전달..
	issuerGenerators, err := issuerPrivateKey.PublicKey().ToPublicKeyWithGenerators(25)
	require.NoError(t, err)

	nonce := bbs.NewProofNonce()

	// holder pre blind secret
	// holder는 holder로 부터 받은 issuergenerators 및 nonce를 이용하여 서명자에게 알려주지 않을 내용에 대하여 미리 서명함..
	secretMsgs := make(map[int][]byte, 0)
	secretMsgs[17] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .`)

	ctx, blinding, err := bbs.NewBlindSignatureContext(secretMsgs, issuerGenerators, nonce)
	require.NoError(t, err)
	require.NotNil(t, blinding)
	require.False(t, blinding.IsZero())
	require.NotNil(t, ctx)

	//require.False(t, ctx.challenge)

	//  holder는 생성한 ctx(blind 서명정보)를 marshaling을 통하여 서명자에게 전달..
	// marshal/unmarshal test
	ctxBytes := ctx.ToBytes()
	require.NotNil(t, ctxBytes)
	nctx := new(bbs.BlindSignatureContext)
	err = nctx.FromBytes(ctxBytes)
	require.NoError(t, err)
	//require.True(t, ctx.challenge.Equal(nctx.challenge))
	//require.True(t, g1.Equal(ctx.commitment, nctx.commitment))
	//require.True(t, g1.Equal(ctx.proofs.commitment, nctx.proofs.commitment))
	//for i, v := range ctx.proofs.responses {
	//	require.True(t, v.Equal(nctx.proofs.responses[i]))
	//}

	// 서명자는 자신에게 공개된 내용에 대하여 서명을 실행
	// holder로 부터 전송받은 ctx에 추가하는 방식
	// signer use known message with index to create blinding signature
	revealedMsg := make(map[int][]byte, 0)
	revealedMsg[0] = []byte(`_:c14n0 <http://purl.org/dc/terms/created> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[1] = []byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`)
	revealedMsg[2] = []byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`)
	revealedMsg[3] = []byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:123456#key1> .`)
	revealedMsg[4] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[5] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .`)
	revealedMsg[6] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .`)
	revealedMsg[7] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .`)
	revealedMsg[8] = []byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> .`)
	revealedMsg[9] = []byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`)
	revealedMsg[10] = []byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`)
	revealedMsg[11] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`)
	revealedMsg[12] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .`)
	revealedMsg[13] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .`)
	revealedMsg[14] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .`)
	revealedMsg[15] = []byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[16] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .`)
	revealedMsg[18] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`)
	revealedMsg[19] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`)
	revealedMsg[20] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`)
	revealedMsg[21] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .`)
	revealedMsg[22] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[23] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`)
	revealedMsg[24] = []byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .`)

	blindSig, err := ctx.ToBlindSignature(revealedMsg, issuerPrivateKey, issuerGenerators, nonce)
	require.NoError(t, err)
	require.NotNil(t, blindSig)

	// holder는 서명자로 부터 blindSig를 전송받아서.. ctx 생성시 만들어진 blinding을 이용하여, unblinding을 수행..
	// holder convert blinding signature to signature
	sig := blindSig.ToUnblinded((*bbs.SignatureBliding)(blinding))
	require.NotNil(t, sig)

	// 전체 내용에 대하여 서명이 이루어 졌는지 확인...
	// verifier verify signature
	allMsg := make([]*bbs.SignatureMessage, 25)
	// allMsg[0] = ParseSignatureMessage([]byte("identity"))
	// allMsg[1] = ParseSignatureMessage([]byte("firstname"))
	// allMsg[2] = ParseSignatureMessage([]byte("password"))
	// allMsg[3] = ParseSignatureMessage([]byte("age"))
	// allMsg[4] = ParseSignatureMessage([]byte("phone number"))
	allMsg[0] = bbs.ParseSignatureMessage([]byte(`_:c14n0 <http://purl.org/dc/terms/created> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[1] = bbs.ParseSignatureMessage([]byte(`_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .`))
	allMsg[2] = bbs.ParseSignatureMessage([]byte(`_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .`))
	allMsg[3] = bbs.ParseSignatureMessage([]byte(`_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:123456#key1> .`))
	allMsg[4] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[5] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .`))
	allMsg[6] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .`))
	allMsg[7] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .`))
	allMsg[8] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> .`))
	allMsg[9] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .`))
	allMsg[10] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .`))
	allMsg[11] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .`))
	allMsg[12] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .`))
	allMsg[13] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .`))
	allMsg[14] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .`))
	allMsg[15] = bbs.ParseSignatureMessage([]byte(`<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[16] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .`))
	allMsg[17] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .`))
	allMsg[18] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .`))
	allMsg[19] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .`))
	allMsg[20] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .`))
	allMsg[21] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .`))
	allMsg[22] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[23] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`))
	allMsg[24] = bbs.ParseSignatureMessage([]byte(`<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .`))

	err = sig.Verify(allMsg, issuerGenerators)
	require.NoError(t, err)
}
