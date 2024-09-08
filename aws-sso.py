#!/usr/bin/env python

import sys
import boto3
import requests
import getpass
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import json
import time
import http.client as httplib
from bs4 import BeautifulSoup
from os.path import expanduser, isfile
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone
import pickle

##########################################################################

# Variables

# region: The default AWS region that this script will connect to for all API calls
region = 'us-west-2'

# output format: The AWS CLI output format that will be configured in the saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate verification is done, False should only be used for dev/test
sslverification = True

# Where to store session cookies for future logins
cookiefile = expanduser('~/.aws/sso_session_cookies')

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://shibboleth2.asu.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices'
duourl = "https://weblogin.asu.edu/cas/login?service=https%3A%2F%2Fshibboleth2.asu.edu%2Fidp%2FAuthn%2FExternal%3Fconversation%3De1s1&entityId=urn%3Aamazon%3Awebservices"

# Validity period for STS token (in seconds)
token_duration = 32400

# Uncomment to enable low level debugging
#httplib.HTTPConnection.debuglevel = 9
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

##########################################################################

# Initiate session handler
session = requests.Session()

# If there is no cached login, or it's expired, go through the login process again
need_login = True
assertion = ''

if isfile(cookiefile):
    with open(cookiefile, 'rb') as f:
        session.cookies.update(pickle.load(f))
    response = session.post(idpentryurl, data={}, verify=sslverification)
    # Uncomment this to print the raw HTML that includes the SAMLResponse
    # print(response.text)
    
    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, 'lxml')
    # Look for the SAMLResponse attribute of the input tag (determined by analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            assertion = inputtag.get('value')
    if (assertion != ''):
        need_login = False

if need_login:
    # Get the federated credentials from the user
    if len(sys.argv) > 4:
        username = sys.argv[1]
        password = sys.argv[2]
        duration = sys.argv[3]
        organization = sys.argv[4]
    else:
        username = input("ASURITE Username: ")
        password = getpass.getpass()
        print('')
        duration = 30
        organization = 'production'

    # Programmatically get the SAML assertion
    # Opens the initial IdP URL and follows all of the HTTP 302 redirects, and gets the resulting login page
    formresponse = session.get(idpentryurl, verify=sslverification)
    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url
    
    # Parse the response and extract all the necessary values in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, 'lxml')
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        if "user" in name.lower():
            payload[name] = username
        elif "email" in name.lower():
            payload[name] = username
        elif "pass" in name.lower():
            payload[name] = password
        elif "auth" in name.lower():
            payload['AuthState'] = value
        else:
            payload[name] = value

    payload['session-duration'] = duration
    payload['organization'] = organization

    response = session.post(
        idpauthformsubmiturl, 
        data=payload, verify=sslverification)

    parenturl = response.url

    username = '##############################################'
    password = '##############################################'
    del username
    del password

    print("Logging you in...")

    soup = BeautifulSoup(response.text, 'lxml')
    datahost = ''
    datasigrequest = ''
    sigresponse = ''

    for iframetag in soup.find_all("iframe", id="duo_iframe"):
        datahost = iframetag['data-host']
        u = iframetag['data-sig-request']
        i = u.find(':APP')
        datasigrequest = u[0:i]
        sigresponseappstr = u[i:len(u)]

    if datahost == '':
        print("Couldn't log you in. Check your username and password.")
        sys.exit(1)

    casexecution = soup.find("input", attrs={"name": "execution"})['value']

    duosession = requests.Session()

    urlpayload = {}
    urlpayload['tx'] = datasigrequest
    urlpayload['parent'] = parenturl
    duoauthurl = "https://" + datahost + "/frame/web/v1/auth" 
    response = duosession.get(duoauthurl, params=urlpayload, verify=sslverification)

    urlpayload['StateId'] = idpauthformsubmiturl
    response = duosession.post(duoauthurl, data=urlpayload, verify=sslverification)
    duourlpromt = response.url

    formresponse = duosession.get(duourlpromt,  verify=sslverification)
    duourlprompt = formresponse.url

    formsoup = BeautifulSoup(formresponse.text, 'lxml')
    payload = {}
    sid = ""

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        if "sid" in name.lower():
            payload[name] = value
            sid = value
        elif "preferred_device" in name.lower():
            payload['device'] = value
        elif "preferred_factor" in name.lower():
            payload['factor'] = value
        elif "out_of_date" in name.lower():
            payload[name] = value

    auth_factor = input('Enter an authentication factor ("push", "phone", "sms") or Duo passcode. Or press enter to use your default factor: ')

    # Only throw up the "press enter after approving" prompt for phone and push flows, it's not needed for SMS or passcode
    wait_for_confirm = True

    if auth_factor == '':
        print(f'Using default auth factor ({payload["factor"]})')
    elif auth_factor == 'push':
        print('Sending a Duo Push to your phone.')
        if 'device' not in payload or payload['device'] == '':
            payload['device'] = 'phone1'
        payload['factor'] = 'Duo Push'
    elif auth_factor == 'phone':
        print('Calling you.')
        if 'device' not in payload or payload['device'] == '':
            payload['device'] = 'phone1'
        payload['factor'] = 'Phone Call'
    elif auth_factor == 'sms':
        payload['factor'] = 'sms'
        session.post(
            duourlprompt,
            data=payload, verify=sslverification)
        passcode = input('Please enter the code we texted you: ')
        payload['factor'] = 'Passcode'
        payload['passcode'] = passcode
        wait_for_confirm = False
    else:
        print('Using passcode.')
        payload['factor'] = 'Passcode'
        payload['passcode'] = auth_factor
        wait_for_confirm = False

    response = session.post(
        duourlprompt,
        data=payload, verify=sslverification)

    duourlprompt = formresponse.url

    d = json.loads(response.text)
    payload = {}
    payload['txid'] = d["response"]["txid"]
    payload['sid'] = sid

    duourlstatus = "https://" + datahost + "/frame/status"

    if wait_for_confirm:
        input("Please press enter after you've accepted the Duo request")

    response = session.post(
    duourlstatus,
    data=payload, verify=sslverification)

    duourlstatus = response.url

    response = session.post(
    duourlstatus + '/' + payload['txid'],
    data=payload, verify=sslverification)

    payload = {}
    d = json.loads(response.text)
    sig_response = d["response"]["cookie"] + sigresponseappstr
    payload["signedDuoResponse"] = sig_response
    payload["_eventId"] = "submit"
    payload["execution"] = casexecution
    parenturl = d["response"]["parent"]
    response = session.post(
    duourl, 
    data=payload, verify=sslverification)

    soup = BeautifulSoup(response.text, 'lxml')

    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            assertion = inputtag.get('value')

    if (assertion == ''):
        print('Response did not contain a valid SAML assertion. Are you being prompted to change your password at login?')
        sys.exit(0)

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn but lots of blogs list it as
# principal_arn,role_arn so let's reverse them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If we get more than one role, ask the user which one they want, otherwise just proceed
print("")
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print(f'[{i}]: {awsrole.split(",")[0]}')
        i += 1
    selectedroleindex = input("Selection: ")

    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    try:
        role_arn = awsroles[0].split(',')[0]
    except IndexError:
        print("Could not find role ARN. Are you sure you logged in with an ID that has AWS access?")
        sys.exit(0)
    principal_arn = awsroles[0].split(',')[1]

with open(cookiefile, 'wb') as f:
    pickle.dump(session.cookies, f)

# Use the assertion to get an AWS STS token using Assume Role with SAML
sts_client = boto3.client('sts', region_name=region)
token = sts_client.assume_role_with_saml(
    RoleArn=role_arn,
    PrincipalArn=principal_arn,
    SAMLAssertion=assertion,
    DurationSeconds=token_duration
)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.ConfigParser()
config.read(filename)

# Put the credentials into a SAML specific section instead of clobbering the default credentials
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set('saml', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set('saml', 'aws_session_token', token['Credentials']['SessionToken'])

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)
    
# Convert UTC time to local time and format it
expiration_utc = token["Credentials"]["Expiration"]
expiration_local = expiration_utc.replace(tzinfo=timezone.utc).astimezone(tz=None)
# Uncomment if you want the date displayed along with the time.
#expiration_formatted = expiration_local.strftime("%m-%d-%Y %I:%M %p")
expiration_formatted = expiration_local.strftime("%I:%M %p")

# Give the user some basic info as to what has just happened
print('\n\n---------------------------------------------------------------------------------------------------------')
print(f'Your new access key pair has been stored in {filename}, in the "saml" profile section.')
print(f'This key pair will expire in {token_duration} seconds, at {expiration_formatted} (in your local timezone).')
print('After this time, you may safely rerun this script to refresh your access key pair.')
print('To use this credential, use the --profile option with your aws CLI commands')
print('For example: aws --profile saml ec2 describe-instances')
print('---------------------------------------------------------------------------------------------------------\n\n')


# Use the AWS STS token to list all of the S3 buckets
s3 = boto3.client('s3',
    aws_access_key_id=token['Credentials']['AccessKeyId'],
    aws_secret_access_key=token['Credentials']['SecretAccessKey'],
    aws_session_token=token['Credentials']['SessionToken'],
    region_name=region
)

buckets = s3.list_buckets()

print('Simple API example listing all S3 buckets:')
for bucket in buckets['Buckets']:
    print(f'  {bucket["Name"]}')
