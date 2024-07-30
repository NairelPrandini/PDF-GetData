# PDF Data Extractor

This Node.js script extracts certificate data from a PDF file. The script reads a PDF file, locates the digital signature information, and extracts the associated certificate details.

## Requirements
- `node-forge` library

## Installation

1. Clone the repository or download the script.
2. Install the required dependencies by running:

    ```bash
    npm install
    ```

## Usage

1. Update the `FilePath` variable in `index.js` to point to your PDF file.

2. Run the script:

    ```bash
    node index.js
    ```

## Code Explanation

### `ExtractCertificateData(FileBuffer)`

Extracts certificate data from the provided PDF buffer.

- **Input**: `FileBuffer` - A buffer containing the PDF data.
- **Output**: An array of certificate data objects.

### `GetSignaturesByteRange(FileBuffer)`

Finds and returns the byte ranges for signatures within the PDF.

- **Input**: `FileBuffer` - A buffer containing the PDF data.
- **Output**: An array of byte ranges.

### `getSignatureData(FileBuffer, ByteRange)`

Extracts the binary data for a signature from the byte range.

- **Input**: `FileBuffer` - A buffer containing the PDF data.
- **Input**: `ByteRange` - An array specifying the byte range.
- **Output**: The binary signature data.

### `GetMessageFromSignature(Signature)`

Converts the signature into a PKCS7 message using `node-forge`.

- **Input**: `Signature` - The binary signature data.
- **Output**: The PKCS7 message object.

### `GetCertificateData(FileBuffer, ByteRange)`

Gets certificate details from the provided byte range.

- **Input**: `FileBuffer` - A buffer containing the PDF data.
- **Input**: `ByteRange` - An array specifying the byte range.
- **Output**: An object with certificate details.

### `MapAttributes(attrs)`

Maps certificate attributes to a key-value object.

- **Input**: `attrs` - An array of attribute objects.
- **Output**: A key-value object representing the attributes.

### `ExtractCertificateDetails(Certificate)`

Extracts and formats certificate details.

- **Input**: `Certificate` - A PKCS7 certificate object.
- **Output**: An object containing the issuer, subject, validity period, and PEM-encoded certificate.

## Example

The provided `index.js` script demonstrates how to use the `ExtractCertificateData` function to extract and print certificate data from a sample PDF.