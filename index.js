const { ExtractCertificateData } = require('./CertificateExtractor');
const fs = require('fs');

const FileBuffer = fs.readFileSync("b.pdf");

// Extract certificate data from the PDF file
const CertificateDataList = ExtractCertificateData(FileBuffer);