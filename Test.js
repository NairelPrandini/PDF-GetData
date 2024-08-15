function a(signature, signedData) {

    const message = getMessageFromSignature(signature);


    const {
        certificates,
        rawCapture: {
            signature: sig,
            authenticatedAttributes: attrs,
            digestAlgorithm,
        },
    } = message;
    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();



    const messageDigestAttr = forge.pki.oids.messageDigest;
    const fullAttrDigest = attrs.find((attr) => forge.asn1.derToOid(attr.value[0].value) === messageDigestAttr);
    const attrDigest = fullAttrDigest.value[1].value[0].value;
    const dataDigest = forge.md[hashAlgorithm]
        .create()
        .update(signedData.toString('latin1'))
        .digest()
        .getBytes();
    const integrity = dataDigest === attrDigest;

    console.log(integrity)
}