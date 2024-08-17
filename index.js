const { ExtractCertificateData } = require('./CertificateExtractor');
const fs = require('fs');

const FileBuffer = fs.readFileSync("TestFiles/SignedDocument-resultado.pdf");

// Extract certificate data from the PDF file
const CertificateDataList = ExtractCertificateData(FileBuffer);

console.log(CertificateDataList);