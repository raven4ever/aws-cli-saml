#!/bin/python3

import base64
import configparser
import getpass
import os
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
output_format = 'yaml'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
aws_config_file_path = '.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
ssl_verification = True

# idpentryurl: The initial url that starts the authentication process.
idp_entry_url = 'https://sts.lseg.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices'

domain_name = 'LSEG'

# AWS profile where the credentials will be saved
profile_name = 'default'

##########################################################################

current_user = getpass.getuser()

# Get the federated credentials from the user
questionary.print(f'!!! Make sure the username includes the domain name as well (eg. {domain_name}\myuser) !!!',
                  style='bold fg:ansired')

username = questionary.text('AD Username:', default=current_user).ask()
password = questionary.password('AD Password:').ask()

region = questionary.text('Default region:', default=region).ask()
output_format = questionary.select('Default output:',
                                   choices=['yaml', 'json'],
                                   default=output_format, use_shortcuts=True, use_arrow_keys=True).ask()

profile_name = questionary.text('AWS profile:', default=profile_name).ask()

# add domain name if not provided
if domain_name not in username:
    username = domain_name + '\\' + username

# Initiate session handler
session = requests.Session()

# Programmatically get the SAML assertion
# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page
formresponse = session.get(idp_entry_url, verify=ssl_verification)

# Capture the idpauthformsubmiturl, which is the final url after all the 302s
idpauthformsubmiturl = formresponse.url

# Parse the response and extract all the necessary values
# in order to build a dictionary of all of the form values the IdP expects
formsoup = BeautifulSoup(formresponse.text, 'html5lib')
payload = {}

for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name', '')
    value = inputtag.get('value', '')
    if 'user' in name.lower():
        # Make an educated guess that this is the right field for the username
        payload[name] = username
    elif 'email' in name.lower():
        # Some IdPs also label the username field as 'email'
        payload[name] = username
    elif 'pass' in name.lower():
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
    if (action and loginid == 'loginForm'):
        parsedurl = urlparse(idp_entry_url)
        idpauthformsubmiturl = parsedurl.scheme + '://' + parsedurl.netloc + action

# Performs the submission of the IdP login form with the above post data
response = session.post(
    idpauthformsubmiturl, data=payload, verify=ssl_verification)

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
    questionary.print('Response did not contain a valid SAML assertion! Try checking your AD credentials.',
                      style='bold fg:ansired')
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
    questionary.print('It seems you can\'t assume any role at this moment. Please contact your AWS account administrator for access!',
                      style='bold fg:ansired')
    sys.exit(0)

role_arn = questionary.select('What role do you want to assume?',
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
path_to_aws_creds = os.path.join(expanduser('~'), aws_config_file_path)

if not os.path.exists(path_to_aws_creds):
    os.makedirs(os.path.dirname(path_to_aws_creds))

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(path_to_aws_creds)

# Put the credentials into a saml specific section instead of clobbering
# the default credentials
if not config.has_section(profile_name):
    config.add_section(profile_name)

config.set(profile_name, 'output', output_format)
config.set(profile_name, 'region', region)
config.set(profile_name, 'aws_access_key_id', token_access_key_id)
config.set(profile_name, 'aws_secret_access_key', token_secret_key)
config.set(profile_name, 'aws_session_token', token_session_token)

# Write the updated config file
with open(path_to_aws_creds, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print('\n')
questionary.print('!' * 46, style='fg:ansibrightgreen')
questionary.print(
    f'Your new access credentials have been stored in the AWS configuration file {path_to_aws_creds} under the default profile.', style='fg:ansibrightgreen')
questionary.print(
    f'The credentials will expire at {token_session_expire.strftime("%a %b %d %H:%M:%S %Z %Y")}!', style='fg:ansibrightgreen')
questionary.print(
    'After this time, you may safely rerun this script to refresh them.', style='fg:ansibrightgreen')
questionary.print(
    'To use this credential, simply call the AWS CLI commands (e.g. aws s3 ls).', style='fg:ansibrightgreen')
questionary.print('!' * 46, style='fg:ansibrightgreen')
print('\n')

# Use the AWS STS token to list all of the S3 buckets
questionary.print(
    f'Listing all buckets in the {region}...', style='fg:ansibrightgreen')
session = boto3.session.Session(region_name=region,
                                aws_access_key_id=token_access_key_id,
                                aws_secret_access_key=token_secret_key,
                                aws_session_token=token_session_token)
s3 = session.resource('s3')
for bucket in s3.buckets.all():
    print(bucket.name)
