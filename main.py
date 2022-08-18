#!/bin/python3

import base64
import configparser
import getpass
import re
import sys
import xml.etree.ElementTree as ET
from os.path import expanduser
from urllib.parse import urlparse

import boto3
import questionary
import requests
from bs4 import BeautifulSoup
from dateutil import tz

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'eu-west-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'yaml'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# idpentryurl: The initial url that starts the authentication process.
# https://sts.company.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices
idpentryurl = ''

##########################################################################

current_user = getpass.getuser()

# Get the federated credentials from the user
username = questionary.text("AD Username:", default=current_user).ask()
password = questionary.password("AD Password:").ask()

region = questionary.text("Default region:", default=region).ask()
outputformat = questionary.select("Default output:",
                                  choices=['yaml', 'json'],
                                  default=outputformat, use_shortcuts=True, use_arrow_keys=True).ask()

# Initiate session handler
session = requests.Session()

# Programmatically get the SAML assertion
# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page
formresponse = session.get(idpentryurl, verify=sslverification)

# Capture the idpauthformsubmiturl, which is the final url after all the 302s
idpauthformsubmiturl = formresponse.url

# Parse the response and extract all the necessary values
# in order to build a dictionary of all of the form values the IdP expects
formsoup = BeautifulSoup(formresponse.text, 'html5lib')
payload = {}

for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name', '')
    value = inputtag.get('value', '')
    if "user" in name.lower():
        # Make an educated guess that this is the right field for the username
        payload[name] = username
    elif "email" in name.lower():
        # Some IdPs also label the username field as 'email'
        payload[name] = username
    elif "pass" in name.lower():
        # Make an educated guess that this is the right field for the password
        payload[name] = password
    else:
        # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# Debug the parameter payload if needed
# Use with caution since this will print sensitive output to the screen
# print payload

# Some IdPs don't explicitly set a form action, but if one is set we should
# build the idpauthformsubmiturl by combining the scheme and hostname
# from the entry url with the form action target
# If the action tag doesn't exist, we just stick with the
# idpauthformsubmiturl above
for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
    action = inputtag.get('action')
    loginid = inputtag.get('id')
    if (action and loginid == "loginForm"):
        parsedurl = urlparse(idpentryurl)
        idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

# Performs the submission of the IdP login form with the above post data
response = session.post(
    idpauthformsubmiturl, data=payload, verify=sslverification)

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

# Decode the response and extract the SAML assertion
soup = BeautifulSoup(response.text, 'html5lib')
assertion = ''

# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if (inputtag.get('name') == 'SAMLResponse'):
        # print(inputtag.get('value'))
        assertion = inputtag.get('value')

# Better error handling is required for production use.
if (assertion == ''):
    # TODO: Insert valid error checking/handling
    print('Response did not contain a valid SAML assertion')
    sys.exit(0)

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if 'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
role_principal_map = {}
if len(awsroles) > 0:
    for awsrole in awsroles:
        role_arn = awsrole.split(',')[0]
        principal_arn = awsrole.split(',')[1]
        role_principal_map[role_arn] = principal_arn
else:
    print('It seems you can\'t assume any role at this moment. Please contact your AWS account administrator for access!')
    sys.exit(0)

role_arn = questionary.select("What role do you want to assume?",
                              choices=role_principal_map, use_shortcuts=True, use_arrow_keys=True).ask()
principal_arn = role_principal_map[role_arn]

# Use the assertion to get an AWS STS token using Assume Role with SAML
sts_client = boto3.client('sts', region_name=region)
token = sts_client.assume_role_with_saml(
    RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)

token_access_key_id = token['Credentials']['AccessKeyId']
token_secret_key = token['Credentials']['SecretAccessKey']
token_session_token = token['Credentials']['SessionToken']
token_session_expire = token['Credentials']['Expiration']

# Convert session expire to local timezone
token_session_expire = token_session_expire.astimezone(tz.tzlocal())

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the credentials into a saml specific section instead of clobbering
# the default credentials
if not config.has_section('default'):
    config.add_section('default')

config.set('default', 'output', outputformat)
config.set('default', 'region', region)
config.set('default', 'aws_access_key_id', token_access_key_id)
config.set('default', 'aws_secret_access_key', token_secret_key)
config.set('default', 'aws_session_token', token_session_token)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print('\n')
print('!' * 46)
print(
    f'Your new access key pair has been stored in the AWS configuration file {filename} under the saml profile.')
print(
    f'The credentials will expire at {token_session_expire.strftime("%a %b %d %H:%M:%S %Z %Y")}!')
print('After this time, you may safely rerun this script to refresh your access key pair.')
print('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml s3 ls).')
print('!' * 46)
print('\n')

# Use the AWS STS token to list all of the S3 buckets
print(f'Listing all buckets in the {region}...')
session = boto3.session.Session(region_name=region,
                                aws_access_key_id=token_access_key_id,
                                aws_secret_access_key=token_secret_key,
                                aws_session_token=token_session_token)
s3 = session.resource('s3')
for bucket in s3.buckets.all():
    print(bucket.name)
