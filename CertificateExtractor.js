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
        FileBuffer.slice(0, ByteRange[0] + ByteRange[1]),
        FileBuffer.slice(ByteRange[2] - 1, (ByteRange[2] - 1) + ByteRange[3])
    ]).toString('binary');

    return (Buffer.from(ByteRangeBuffer, 'hex')).toString('binary');
}

function GetMessageFromSignature(Signature) {
    const p7Asn1 = forge.asn1.fromDer(Signature, { parseAllBytes: false });
    return forge.pkcs7.messageFromAsn1(p7Asn1);
}

function GetCertificateData(FileBuffer, ByteRange) {
    const SignatureData = GetSignatureData(FileBuffer, ByteRange);
    const SignedData = GetSignedData(FileBuffer, ByteRange);
    const Message = GetMessageFromSignature(SignatureData);

    const Details = ExtractCertificateDetails(Message.certificates[0]);

    return Details;

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