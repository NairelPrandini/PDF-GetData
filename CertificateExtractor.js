const forge = require("node-forge");
const { Buffer } = require("buffer");

function ExtractCertificateData(FileBuffer) {
    const ByteRangeList = GetSignaturesByteRanges(FileBuffer);

    const CertificateDataList = ByteRangeList.map((ByteRange) => {
        const CertificateData = GetCertificateData(FileBuffer, ByteRange);
        return CertificateData;
    });

    return CertificateDataList;
}

function GetSignaturesByteRanges(FileBuffer) {
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

function GetSignatureBuffer(FileBuffer, ByteRange) {
    // Extract the specified range from the buffer
    let ByteRangeBuffer = FileBuffer.slice(ByteRange[1] + 1, ByteRange[2] - 1).toString('binary');
    return (Buffer.from(ByteRangeBuffer, 'hex')).toString('binary');
}

function GetSignedBuffer(FileBuffer, ByteRange) {

    // Extract the specified range from the buffer
    let ByteRangeBuffer = Buffer.concat([
        FileBuffer.slice(ByteRange[0], ByteRange[0] + ByteRange[1]),
        FileBuffer.slice(ByteRange[2], ByteRange[2] + ByteRange[3])
    ]);

    return Buffer.from(ByteRangeBuffer);
}

function GetMessageFromSignature(SignatureBuffer) {
    const p7Asn1 = forge.asn1.fromDer(SignatureBuffer, { parseAllBytes: false });
    return forge.pkcs7.messageFromAsn1(p7Asn1);
}


function ParseAdvancedSignatureData(Message) {

    const ParsedData = {};
    const Certificate = Message.certificates[0];

    ParsedData.version = Certificate.version;
    ParsedData.serialNumber = Certificate.serialNumber.toString(16);
    ParsedData.signatureOid = Certificate.signatureOid;
    ParsedData.signature = forge.util.bytesToHex(Certificate.signature);

    ParsedData.validity = {
        notBefore: Certificate.validity.notBefore,
        notAfter: Certificate.validity.notAfter,
    };

    ParsedData.issuer = Certificate.issuer.attributes.map(attr => ({
        name: attr.name,
        value: attr.value,
    }));

    ParsedData.subject = Certificate.subject.attributes.map(attr => ({
        name: attr.name,
        value: attr.value,
    }));
    ParsedData.extensions = Certificate.extensions.map(ext => ({
        id: ext.id,
        name: ext.name,
        value: forge.util.bytesToHex(ext.value),
        critical: ext.critical,
    }));
    ParsedData.publicKey = {
        n: Certificate.publicKey.n.toString(16),
        e: Certificate.publicKey.e.toString(16),
    };

    ParsedData.isExpired = Certificate.validity.notAfter.getTime() < Date.now() || Certificate.validity.notBefore.getTime() > Date.now();

    ParsedData.pemCertificate = forge.pki.certificateToPem(Certificate);

    return ParsedData;
}

// Assuming forge is already imported and SignedData is a Buffer object

function SignedDataHashHex(SignedData, Algorithm) {
    // Create a new hash object using the specified algorithm
    const md = forge.md[Algorithm].create().update(SignedData.toString('binary'));
    const Digest = md.digest().getBytes();
    return (Buffer.from(Digest)).toString('hex');
}

function VerifyIntegrity(SignatureMessage, SignedData) {

    const attrs = SignatureMessage.rawCapture.authenticatedAttributes; // Extract authenticated attributes
    const digestAlgorithm = SignatureMessage.rawCapture.digestAlgorithm; // Extract digest algorithm

    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();

    const messageDigestAttr = forge.pki.oids.messageDigest;
    const fullAttrDigest = attrs.find((attr) => forge.asn1.derToOid(attr.value[0].value) === messageDigestAttr);

    if (!fullAttrDigest) {
        console.error('MessageDigest attribute not found in authenticated attributes.');
        return false;
    }

    const attrDigest = Buffer.from(fullAttrDigest.value[1].value[0].value).toString('hex');

    const SignedDataDigest = SignedDataHashHex(SignedData, hashAlgorithm);

    return (SignedDataDigest === attrDigest);
}

function VerifyExpiration(Certificate) {
    return Certificate.validity.notAfter.getTime() < Date.now() || Certificate.validity.notBefore.getTime() > Date.now();
}

function MapAttributes(attrs) {
    return attrs.reduce((item, { name, value }) => {
        if (name) { item[name] = value }
        return item;
    }, {});
}

function ExtractCertificateDetails(Message) {

    const Certificate = Message.certificates[0];

    if (!Certificate) { return }

    return {
        issuedBy: MapAttributes(Certificate.issuer.attributes),
        issuedTo: MapAttributes(Certificate.subject.attributes),
        validityPeriod: Certificate.validity,
        pemCertificate: forge.pki.certificateToPem(Certificate),
        isExpired: VerifyExpiration(Certificate),
    };
}

function GetCertificateData(FileBuffer, ByteRange) {

    const SignatureBuffer = GetSignatureBuffer(FileBuffer, ByteRange);

    const SignedBuffer = GetSignedBuffer(FileBuffer, ByteRange);

    const SignatureMessage = GetMessageFromSignature(SignatureBuffer);

    const CertificateData = ExtractCertificateDetails(SignatureMessage);

    //const AdvancedData = ParseAdvancedSignatureData(SignatureMessage);

    CertificateData.validIntegrity = VerifyIntegrity(SignatureMessage, SignedBuffer);

    return { CertificateData };

}

module.exports = { ExtractCertificateData };