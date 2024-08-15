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

### `ExtractCertificateData(FileBuffer)`

Extracts certificate data from the provided PDF buffer.

- **Input**: `FileBuffer` - A buffer containing the PDF data.
- **Output**: An object containing the issuer, subject, validity period, and PEM-encoded certificate.

## Example

The provided `index.js` script demonstrates how to use the `ExtractCertificateData` function to extract and print certificate data from a sample PDF.