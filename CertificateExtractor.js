const forge = require("node-forge");
const fs = require("fs");
const { Buffer } = require("buffer");

function ExtractCertificateData(FileBuffer) {
    const ByteRangeList = GetSignaturesByteRange(FileBuffer);

    const CertificateDataList = ByteRangeList.map((ByteRange) => {
        const CertificateData = GetCertificateData(FileBuffer, ByteRange);
        return CertificateData;
    });

    return CertificateDataList;
}

function GetSignaturesByteRange(FileBuffer) {
    const ByteRangeList = [];
    let ByteRangeStart = 0;

    while ((ByteRangeStart = FileBuffer.indexOf("/ByteRange [", ByteRangeStart)) !== -1) {
        const ByteRangeEnd = FileBuffer.indexOf("]", ByteRangeStart);
        const ByteRange = FileBuffer.slice(ByteRangeStart, ByteRangeEnd + 1).toString();
        const ByteRangeString = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(ByteRange);
        const ByteRangeArray = ByteRangeString.slice(1, 5).map(Number); // Convert to integers

        // Add the ByteRange to the list
        ByteRangeList.push(ByteRangeArray);

        // Move past the current ByteRange
        ByteRangeStart = ByteRangeEnd + 1;
    }

    return ByteRangeList;
}

function GetSignatureData(FileBuffer, ByteRange) {
    // Extract the specified range from the buffer
    let ByteRangeBuffer = FileBuffer.slice(ByteRange[1] + 1, ByteRange[2] - 1).toString('binary');
    return (Buffer.from(ByteRangeBuffer, 'hex')).toString('binary');
}

function GetSignedData(FileBuffer, ByteRange) {

    // Extract the specified range from the buffer
    let ByteRangeBuffer = Buffer.concat([
        FileBuffer.slice(ByteRange[0], ByteRange[0] + ByteRange[1]),
        FileBuffer.slice(ByteRange[2], ByteRange[2] + ByteRange[3])
    ]).toString('binary');

    return (Buffer.from(ByteRangeBuffer, 'hex')).toString('binary');
}

function GetMessageFromSignature(Signature) {
    const p7Asn1 = forge.asn1.fromDer(Signature, { parseAllBytes: false });
    return forge.pkcs7.messageFromAsn1(p7Asn1);
}

function VerifyDataIntegrity(SignatureData, SignedData, Message) {

    if (!Message || !Message.certificates || !Message.certificates.length) { return }


    const {
        rawCapture: {
            authenticatedAttributes: attrs,
            digestAlgorithm,
        },
    } = Message;


    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();


    const messageDigestAttr = forge.pki.oids.messageDigest;
    const fullAttrDigest = attrs.find((attr) => forge.asn1.derToOid(attr.value[0].value) === messageDigestAttr);
    const attrDigest = fullAttrDigest.value[1].value[0].value;
    const dataDigest = forge.md[hashAlgorithm].create().update(SignedData.toString('binary')).digest().getBytes();


    const integrity = dataDigest === attrDigest;

    return integrity;

}

function GetCertificateData(FileBuffer, ByteRange) {
    const SignatureData = GetSignatureData(FileBuffer, ByteRange);
    const SignedData = GetSignedData(FileBuffer, ByteRange);
    const Message = GetMessageFromSignature(SignatureData);


    const integrity = VerifyDataIntegrity(SignatureData, SignedData, Message);
    const Details = ExtractCertificateDetails(Message.certificates[0]);

    console.log(Details);
    console.log(integrity);
}

function MapAttributes(attrs) {
    return attrs.reduce((item, { name, value }) => {
        if (name) { item[name] = value }
        return item;
    }, {});
}

function ExtractCertificateDetails(Certificate) {

    if (!Certificate) { return }

    const isExpired = Certificate.validity.notAfter.getTime() < Date.now() || Certificate.validity.notBefore.getTime() > Date.now();

    return {
        issuedBy: MapAttributes(Certificate.issuer.attributes),
        issuedTo: MapAttributes(Certificate.subject.attributes),
        validityPeriod: Certificate.validity,
        pemCertificate: forge.pki.certificateToPem(Certificate),
        isExpired: isExpired
    };
}

module.exports = { ExtractCertificateData };