const forge = require("node-forge");
const fs = require("fs");
const { Buffer } = require("buffer");

function ExtractCertificateData(FileBuffer) {
    const ByteRangeList = GetSignaturesByteRange(FileBuffer);

    const CertificateDataList = ByteRangeList.map((ByteRange) => {
        const CertificateData = GetCertificateData(FileBuffer, ByteRange);
        return CertificateData;
    }).filter(data => data !== undefined);

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

function getSignatureData(FileBuffer, ByteRange) {
    // Extract the specified range from the buffer
    let ByteRangeBuffer = FileBuffer.slice(ByteRange[1] + 1, ByteRange[2] - 1).toString('binary');

    // Remove the zeroes from the end of the buffer
    let EndIndex = ByteRangeBuffer.length;
    while (EndIndex > 0 && ByteRangeBuffer[EndIndex - 1] === 0x30) {
        EndIndex--;
    }

    ByteRangeBuffer = ByteRangeBuffer.slice(0, EndIndex);
    return (Buffer.from(ByteRangeBuffer, 'hex')).toString('binary');
}

function GetMessageFromSignature(Signature) {
    const p7Asn1 = forge.asn1.fromDer(Signature, { parseAllBytes: false });
    return forge.pkcs7.messageFromAsn1(p7Asn1);
}

function GetCertificateData(FileBuffer, ByteRange) {
    const SignatureData = getSignatureData(FileBuffer, ByteRange);
    const Message = GetMessageFromSignature(SignatureData);

    const Certificate = Message.certificates[0];

    if (!Certificate) { return }

    return ExtractCertificateDetails(Certificate);
}

function MapAttributes(attrs) {
    return attrs.reduce((agg, { name, value }) => {
        if (name) {
            agg[name] = value;
        }
        return agg;
    }, {});
}

function ExtractCertificateDetails(Certificate) {
    return {
        issuedBy: MapAttributes(Certificate.issuer.attributes),
        issuedTo: MapAttributes(Certificate.subject.attributes),
        validityPeriod: Certificate.validity,
        pemCertificate: forge.pki.certificateToPem(Certificate),
    };
}

module.exports = { ExtractCertificateData };