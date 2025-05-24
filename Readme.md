# Hotel Booking Platform - AWS Microservices

A cloud-native hotel booking platform built using AWS serverless microservices architecture. This project demonstrates modern cloud development practices with event-driven architecture, CQRS pattern implementation, and role-based access control.

## 🚀 Current Progress: ~50% Complete

### ✅ Implemented Features

#### 🔐 Authentication & Authorization

- **AWS Cognito** integration for user management
- **Admin user groups** with role-based access control
- **Custom Lambda Authorizer** for JWT token validation
- Sign-in/sign-out navigation flows

#### 🏨 Hotel Management (Admin Features)

- **Hotel Registration**: Admins can add new hotels to the platform
- **Hotel Data**: Name, rating, price, location, and image upload
- **Admin-Specific Views**: Admins can only see hotels they've added
- **File Upload**: S3 integration for hotel images

#### 🔧 API Infrastructure

- **RESTful APIs** with AWS API Gateway
- **Proxy resources** for flexible routing
- **CORS enablement** for cross-origin requests
- **Multiple deployment stages**

#### 📊 Data Architecture (CQRS Pattern)

- **Write Operations**: DynamoDB for transactional data
- **Read Operations**: OpenSearch for complex queries and search
- **Event Sourcing**: SNS-based event bus for data consistency
- **File Storage**: S3 buckets for hotel images

#### 🔄 Event-Driven Processing

```
addHotel Lambda → SNS Topic → Event Handler Lambda → DynamoDB & OpenSearch
```

## 🛠️ Technical Stack

### AWS Services

- **Compute**: AWS Lambda (Python)
- **API Management**: AWS API Gateway
- **Authentication**: AWS Cognito
- **Storage**: Amazon S3, DynamoDB
- **Search**: Amazon OpenSearch Service
- **Messaging**: Amazon SNS
- **Security**: IAM Roles and Policies

### Development Tools

- **Language**: Python
- **Containerization**: Docker (for Lambda layers)
- **Frontend**: Plain HTML/CSS
- **Dependencies**: Lambda Layers for shared libraries

## 🚀 Deployment Guide

### Prerequisites

- AWS CLI configured with appropriate permissions
- Docker installed for building Lambda layers
- Python 3.9+ for Lambda functions

### Step 1: Authentication Setup

```bash
# Create Cognito User Pool and configure admin groups
# Set up IAM roles for Lambda execution
```

### Step 2: Database Setup

```bash
# Create DynamoDB tables
# Set up OpenSearch domain
# Configure S3 buckets with proper permissions
```

### Step 3: Lambda Deployment

```bash
# Build Python dependencies layer
docker build -t lambda-layer .
docker run --rm lambda-layer cat layer.zip > dependencies-layer.zip

# Deploy Lambda functions with layers
aws lambda create-function --function-name addHotel --runtime python3.9
aws lambda create-function --function-name listHotel --runtime python3.9
```

### Step 4: API Gateway Configuration

```bash
# Create API Gateway with proxy resources
# Configure CORS and deployment stages
# Attach Lambda authorizer
```

## 🔧 Configuration

### Environment Variables

```env
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
S3_BUCKET_NAME=hotel-platform-images
DYNAMODB_TABLE_NAME=Hotels
OPENSEARCH_ENDPOINT=https://search-hotels-xxxxx.us-east-1.es.amazonaws.com
SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:hotel-events
```

## 🔒 Security Features

- **JWT Token Validation** (Development mode - signature verification disabled)
- **Role-Based Access Control** via Cognito user groups
- **API Gateway Authorization** with custom Lambda authorizer
- **S3 Bucket Policies** for secure file access
- **IAM Least Privilege** principles

> ⚠️ **Security Note**: Current JWT authorizer doesn't verify signatures for development ease. Production deployment requires proper signature verification.

## 📊 Monitoring

- **CloudWatch Logs** for Lambda function execution
- **API Gateway Metrics** for request/response monitoring
- **S3 Request Metrics** for file upload tracking
- **DynamoDB Metrics** for database performance

## 🚧 Upcoming Features (Remaining 50%)

- [ ] **Customer User Registration** and management
- [ ] **Hotel Search & Filtering** (leveraging OpenSearch)
- [ ] **Booking System** with availability tracking
- [ ] **Production Security** hardening

## 🐛 Known Issues

1. **JWT Signature Verification**: Disabled due to cryptography dependency issues
2. **CORS Configuration**: May need adjustment for production domains
3. **Error Handling**: Basic implementation, needs enhancement for production

## 📚 Documentation

- [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
- [API Gateway Setup Guide](https://docs.aws.amazon.com/apigateway/)
- [Cognito Authentication](https://docs.aws.amazon.com/cognito/)
- [OpenSearch Service](https://docs.aws.amazon.com/opensearch-service/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create a Pull Request

---

**Project Status**: 🔄 Active Development | **Next Milestone**: Customer Booking System
