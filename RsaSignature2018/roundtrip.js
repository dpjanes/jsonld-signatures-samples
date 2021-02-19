// to generate the next two lines, run the following command:
//
// openssl genrsa -out key.pem; cat key.pem; 
// openssl rsa -in key.pem -pubout -out pubkey.pem;
// cat pubkey.pem; rm key.pem pubkey.pem
//
// for an example of how to specify these keys, look at [key-example]:

const jsigs = require("jsonld-signatures")
const fs = require("fs")
const {RsaSignature2018} = jsigs.suites;
const {AssertionProofPurpose} = jsigs.purposes;
const {RSAKeyPair} = require("crypto-ld");
const {documentLoaders} = require("jsonld");

const SAMPLE_KEY_ID = "https://example.com/i/alice/keys/1"
const documents = {}

/**
 *  JSON-LD requires a custom document loader to pull
 *  in random data from the Internet.
 *
 *  In this case, the random information is the public key for verifying 
 *  
 *  This is our customer document loader.
 *  It will check our documents, the just 
 *  do the default thing.
 */
const document_loader = url => {
    const context = documents[url]

    if (context) {
        return {
            contextUrl: null, // this is for a context via a link header
            document: context, // this is the actual document that was loaded
            documentUrl: url // this is the actual context URL after redirects
        }
    }

    return documentLoaders.node()(url);
};

 
const run = async (paramd) => {
    /**
     *  The PEM file is wrapped up in some JSON-LD
     *  and put into "documents" so it can be 
     *  discovered during verification.
     */
    const publicKey = {
        "@context": jsigs.SECURITY_CONTEXT_URL,
        type: "RsaVerificationKey2018",
        id: SAMPLE_KEY_ID,
        controller: "https://example.com/i/alice",
        publicKeyPem: await fs.promises.readFile("key.public.pem", "utf-8")
    }
    documents[SAMPLE_KEY_ID] = publicKey

    // specify the public key controller object (whatevery the hell that is)
    const controller = {
        "@context": jsigs.SECURITY_CONTEXT_URL,
        id: "https://example.com/i/alice",
        publicKey: [publicKey],
        // this authorizes this key to be used for making assertions
        assertionMethod: [publicKey.id]
    };

    const keypair_with_private = new RSAKeyPair({
        ...publicKey, 
        privateKeyPem: await fs.promises.readFile("key.private.pem", "utf-8"),
    });
    const keypair_without_private = new RSAKeyPair({
        ...publicKey, 
        privateKeyPem: await fs.promises.readFile("key.private.pem", "utf-8"),
    });

    // sign the document as a simple assertion
    const signed = await jsigs.sign(paramd.document, {
        suite: new RsaSignature2018({
            key: keypair_with_private,
        }),
        purpose: new AssertionProofPurpose()
    });

    console.log()
    console.log("Signed:", JSON.stringify(signed, null, 2))

    // verify the signed document
    const result = await jsigs.verify(signed, {
        documentLoader: document_loader,
        suite: new RsaSignature2018(keypair_without_private),
        purpose: new AssertionProofPurpose({
            controller,
        })
    });

    console.log("")
    if (result.verified) {
        console.log("Signature verified!.");
    } else {
        console.log("Signature verification error:", result.error);
    }
}

run({
    document: require("./document.json"),
}).catch(error => {
    console.log(error)
})


