const jlds = require("jsonld-signatures")
const fs = require("fs")
const jsonld = require("jsonld")
const cryptold = require("crypto-ld")

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

    return jsonld.documentLoaders.node()(url);
};

 
const run = async (paramd) => {
    /**
     *  The PEM file is wrapped up in some JSON-LD
     *  and put into "documents" so it can be 
     *  discovered during verification.
     */
    const publicKey = {
        "@context": jlds.SECURITY_CONTEXT_URL,
        type: "RsaVerificationKey2018",
        id: SAMPLE_KEY_ID,
        controller: "https://example.com/i/alice", // … this doesn't see to do anything
        publicKeyPem: await fs.promises.readFile("ppk/public.pem", "utf-8")
    }
    documents[SAMPLE_KEY_ID] = publicKey

    /**
     *  PRIVATE PART - signing
     */
    const keypair_with_private = new cryptold.RSAKeyPair({
        ...publicKey, 
        privateKeyPem: await fs.promises.readFile("ppk/private.pem", "utf-8"),
    });
    const suite_with_private = new jlds.suites.RsaSignature2018({
        key: keypair_with_private,
        // date: new Date(),

    })

    // sign the document as a simple assertion
    const signed = await jlds.sign(paramd.document, {
        suite: suite_with_private,
        purpose: new jlds.purposes.AssertionProofPurpose()
    });

    console.log()
    console.log("Signed:", JSON.stringify(signed, null, 2))

    /**
     *  PUBLIC PART - verification
     */
    // specify the public key controller object (whatevery the hell that is)
    const controller = {
        "@context": jlds.SECURITY_CONTEXT_URL,
        id: "https://example.com/i/alice", // … this doesn't see to do anything
        publicKey: [ publicKey ],
        // this authorizes this key to be used for making assertions
        assertionMethod: [ publicKey.id ]
    };

    const keypair_without_private = new cryptold.RSAKeyPair({
        ...publicKey, 
    });
    const suite_without_private = new jlds.suites.RsaSignature2018(keypair_without_private)

    // verify the signed document
    const result = await jlds.verify(signed, {
        documentLoader: document_loader,
        suite: suite_without_private,
        purpose: new jlds.purposes.AssertionProofPurpose({
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
