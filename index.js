const { ExtractCertificateData } = require('./CertificateExtractor');
const fs = require('fs');

const FilePath = "./files/Relatório tutoria - Junho.pdf"; // Replace with your PDF file path

const FileBuffer = fs.readFileSync(FilePath);

// Extract certificate data from the PDF file
const CertificateDataList = ExtractCertificateData(FileBuffer);

// Print the extracted certificate data
console.log("Extracted Certificate Data:");
CertificateDataList.forEach((certData, index) => {
    console.log(`Certificate ${index + 1}:`);
    console.log(`Issued By:`, certData.issuedBy);
    console.log(`Issued To:`, certData.issuedTo);
    console.log(`Validity Period:`, certData.validityPeriod);
    console.log(`PEM Certificate:\n`, certData.pemCertificate);
});
