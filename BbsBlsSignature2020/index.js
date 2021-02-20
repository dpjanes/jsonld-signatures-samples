/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const {
  Bls12381G2KeyPair,
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} = require("@mattrglobal/jsonld-signatures-bbs")

const { extendContextLoader, sign, verify, purposes } = require("jsonld-signatures");
const { documentLoaders } = require("jsonld");

const inputDocument = require("./data/inputDocument.json")
const keyPairOptions = require("./data/keyPair.json")
const exampleControllerDoc = require("./data/controllerDocument.json")
const bbsContext = require("./data/lds-bbsbls2020-v0.0.json")
const revealDocument = require("./data/deriveProofFrame.json")
const citizenVocab = require("./data/citizenVocab.json")

const documents = {
  "did:example:489398593#test": keyPairOptions,
  "did:example:489398593": exampleControllerDoc,
  "https://w3c-ccg.github.io/ldp-bbs2020/context/v1": bbsContext,
  "https://w3id.org/citizenship/v1": citizenVocab
};

const customDocLoader = url => {
  const context = documents[url];

  if (context) {
    return {
      contextUrl: null, // this is for a context via a link header
      document: context, // this is the actual document that was loaded
      documentUrl: url // this is the actual context URL after redirects
    };
  }

  return documentLoaders.node()(url);
};

//Extended document load that uses local contexts
const documentLoader = extendContextLoader(customDocLoader);

const main = async () => {
  //Import the example key pair
  const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

  console.log("Input document");
  console.log(JSON.stringify(inputDocument, null, 2));

  //Sign the input document
  const signedDocument = await sign(inputDocument, {
    suite: new BbsBlsSignature2020({ key: keyPair }),
    purpose: new purposes.AssertionProofPurpose(),
    documentLoader
  });

  console.log()
  console.log("Input document with proof");
  console.log(JSON.stringify(inputDocument, null, 2));

  //Verify the proof
  let verified = await verify(inputDocument, {
    suite: new BbsBlsSignature2020(),
    purpose: new purposes.AssertionProofPurpose(),
    documentLoader
  });

  console.log()
  console.log("Verification result");
  console.log(JSON.stringify(verified, null, 2));

  //Derive a proof
  const derivedProof = await deriveProof(inputDocument, revealDocument, {
    suite: new BbsBlsSignatureProof2020(),
    documentLoader
  });

  console.log()
  console.log("Reveal Document")
  console.log(JSON.stringify(revealDocument, null, 2));

  console.log()
  console.log("Derived Proof")
  console.log(JSON.stringify(derivedProof, null, 2));

  //Verify the derived proof
  verified = await verify(derivedProof, {
    suite: new BbsBlsSignatureProof2020(),
    purpose: new purposes.AssertionProofPurpose(),
    documentLoader
  });

  console.log()
  console.log("Verification result");
  console.log(JSON.stringify(verified, null, 2));
};

main().catch(error => console.log(error))
