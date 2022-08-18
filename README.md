# AWS SAML CLI

## Scope

The scope of this application is to offer a mechanism to set up AWS credentials on the local machine using the corporate [STS URL](https://sts.company.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices).

## How it works

The application will ask the user to enter its Active Directory credentials and to set the AWS default values for the `region` and `output` variables. By default, the application will offer default values for these variables. The default values are:

- `user`: currently logged user
- `region`: eu-west-1
- `output`: yaml

After gathering this information, the application will login to the STS URL using the provided credentials and will retrieve a list of roles the user can assume. The list of roles contains the fully qualified names of the roles. The user is expected to input a number from 0 to n which will corespond to the role to be assumed.

The application will retrieve a set of values for the `AccessKeyId`, `SecretAccessKey` and `SessionToken` items. These values will be stored in the AWS credentials file from the home directory of the current user. The credentials (`aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`) and the configuration (`region`, `output`) will be set under a new profile named `saml`.

Because the credentials have an expire date, the application will output a message with the expiration date & time.

To verify the credentials, the application will attempt to list all the S3 buckets from the region specified in the configuration.

The implementation is an adaptation for Python3 based on an [AWS Blog Post](https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/).

## Requirements

To run this application the following requirements need to be met:

- Python 3.6 installed
- AWS CLI v2 installed
- Python dependencies installed:

    ```shell
    pip3 install -r requirements.txt
    ```

## Usage

To run the application run:

```shell
./main.py
```
