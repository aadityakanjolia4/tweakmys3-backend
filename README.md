# Cloud JSON Viewer API

A Flask-based REST API that enables seamless viewing and editing of JSON files stored in AWS S3 buckets and Azure Blob Storage.

## 🚀 Features


- **Multiple Storage Providers**: Supports both AWS S3 and Azure Blob Storage
- **Multiple S3 URL Formats**: Supports various S3 URL formats (s3://, virtual-hosted-style, path-style)
- **Azure Blob URL Support**: Supports Azure Blob Storage URLs
- **JSON Editing**: Load, edit, and save JSON files back to cloud storage
- **Smart JSON Parsing**: Automatically beautifies nested JSON strings
- **Error Handling**: Comprehensive error handling for AWS and Azure operations
- **Health Monitoring**: Built-in health check and CORS testing endpoints
- **Vercel Deployment**: Pre-configured for easy Vercel deployment

## 📋 Prerequisites

- Python 3.7+
- AWS Account with S3 access (for S3 operations)
- Azure Storage Account (for Blob Storage operations)


## 🌐 API Endpoints

### Health Check
```http
GET /health
```
Returns API status and S3 client availability.


### Fetch JSON from Cloud Storage
```http
POST /api/get-json
Content-Type: application/json

{
  "s3_url": "s3://your-bucket/path/to/file.json"
}
```
*or*
```http
POST /api/get-json
Content-Type: application/json

{
  "blob_url": "https://yourstorageaccount.blob.core.windows.net/container/path/to/file.json"
}
```


## 📄 License

This project is open source. Please check the license file for details.

