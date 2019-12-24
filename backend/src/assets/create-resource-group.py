#!/usr/bin/env python3
# create-resource-group.py - A script to generate a resource group and admin and user access groups for access
# Author: Jon Hall
# Copyright (c) 2019
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Resource Manager API: https://cloud.ibm.com/apidocs/resource-controller/resource-manager
# Resource Controller API: https://cloud.ibm.com/apidocs/resource-controller/resource-controller
# User Management API https://cloud.ibm.com/apidocs/user-management#invite-users
# IAM Identity API: https://cloud.ibm.com/apidocs/iam-identity-token-api
# IAM Access Groups: https://cloud.ibm.com/apidocs/iam-access-groups
# IAM Policy Mgmt: https://cloud.ibm.com/apidocs/iam-policy-management
#
######################################################################


import requests, json, time, sys, os, argparse, urllib

def getiamtoken():
    ################################################
    ## Get Bearer Token using apiKey
    ################################################

    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/json"}

    parms = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": apiKey}

    try:
        resp = requests.post(iam_endpoint + "/identity/token?" + urllib.parse.urlencode(parms),
                             headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        print("Invalid token request.")
        print("template=%s" % parms)
        print("Error Data:  %s" % errb)
        print("Other Data:  %s" % resp.text)
        quit()

    iam = resp.json()

    iamtoken = {"Authorization": "Bearer " + iam["access_token"]}

    return iamtoken

def getresourcegroups():
    # Get a list of current resource groups in accountId
    try:
        resp = requests.get(resource_controller_endpoint + '/v2/resource_groups?account_id=' + accountId,  headers=iamToken, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        if resp.status_code == 400:
            print("Invalid Request.")
            print("Error Data: %s" % errb)
            quit()
        elif resp.status_code == 401:
            print("Your access token is invalid or authentication of your token failed.")
            quit()
        elif resp.status_code == 403:
            print("Your access token is valid but does not have the necessary permissions to access this resource.")
            quit()
        else:
            unknownapierror(resp)

    if resp.status_code == 200:
        resourceGroups = json.loads(resp.content)["resources"]
    else:
        print ("Unexpected Error getting resource-groups, error code = %s." % (resp.status_code))
        quit()

    return resourceGroups

def createresourcegroup(resourceGroupName):
    # Create new resource group

    parms = {
        "name": resourceGroupName,
        "account_id": accountId
    }

    try:
        resp = requests.post(resource_controller_endpoint + '/v2/resource_groups' , json=parms, headers=iamToken, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        if resp.status_code == 400:
            print("The request could have invalid payload")
            print("template: %s" % parms)
            print("Error Data: %s" % errb)
            quit()
        elif resp.status_code == 401:
            print("Your access token is invalid or authentication of your token failed.")
            quit()
        elif resp.status_code == 403:
            print("Your access token is valid but does not have the necessary permissions to access this resource.")
            quit()
        else:
            unknownapierror(resp)

    if resp.status_code == 201:
        resourceGroupId = resp.json()["id"]
        print("resource-group %s (%s) was created successfully." % (resourceGroupName, resourceGroupId))
    else:
        print("Unexpected result.")
        quit()

    return resourceGroupId

def getresourcegroupid(resourceGroupName):
    # search list for resource groups for resourceGroup and return ID

    resourceGroup = list(filter(lambda resourceGroup: resourceGroup['name'] == resourceGroupName, resourceGroups))

    if len(resourceGroup) > 0:
            resourceGroupId = resourceGroup[0]['id']
    else:
        resourceGroupId = None

    return resourceGroupId

def getdefaultresourcegroupid():
    # search list for resource groups for resourceGroup and return ID

    resourceGroup = list(filter(lambda resourceGroup: resourceGroup['default'] == True, resourceGroups))

    if len(resourceGroup) > 0:
            resourceGroupId = resourceGroup[0]['id']
            resourceGroupName = resourceGroup[0]['name']
    else:
        resourceGroupId = None
        resourceGroupName = None

    return resourceGroupId, resourceGroupName

def getusers():
    # Get a list of current users in accountId
    users = []
    offset = 0
    limit = 100
    url = user_management_endpoint + '/v2/accounts/' + accountId + "/users?limit=" + str(limit) + "&offset=" + str(offset)
    while True:
        try:
            resp = requests.get(url,  headers=iamToken, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting:", errc)
            quit()
        except requests.exceptions.Timeout as errt:
            print("Timeout Error:", errt)
            quit()
        except requests.exceptions.HTTPError as errb:
            if resp.status_code == 401:
                print("Your access token is invalid or authentication of your token failed.")
                quit()
            elif resp.status_code == 403:
                print("Your access token is valid but does not have the necessary permissions to access this resource.")
                quit()
            else:
                unknownapierror(resp)

        if resp.status_code == 200:
            users = users + json.loads(resp.content)["resources"]
            if "next" in json.loads(resp.content):
                url = json.loads(resp.content)["next"]["href"]
            else:
                break
        else:
            print ("Unexpected error getting user list, error code = %s." % (resp.status_code))
            quit()

    return users

def getuserid(email):
    # Get User Id from list
    user = list(filter(lambda user: user['email'] == email, users))

    if len(user) > 0:
        userId = user[0]['id']
        userIamId = user[0]['iam_id']
        userState = user[0]['state']
    else:
        userId = None
        userIamId = None
        userState = None

    return userId, userIamId, userState

def inviteuserid(email, resourceGroupId):
    # Invites a new user to account & give Administrator access to resource group

    parms = {
        "users": [
            {"email": email,
            "account_role": "Member"}
        ],
        "iam_policy": [
            {"roles": [ { "id": "crn:v1:bluemix:public:iam::::role:Administrator"}],
             "resources": [{
                "accountId": accountId,
                "resourceType": "resource-group",
                "resource": resourceGroupId}]
            }
        ]
    }

    try:
        resp = requests.post(user_management_endpoint + '/v2/accounts/' + accountId + "/users" , json=parms, headers=iamToken, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        if resp.status_code == 401:
            print("Your access token is invalid or authentication of your token failed.")
            quit()
        elif resp.status_code == 403:
            print("Your access token is valid but does not have the necessary permissions to access this resource.")
            quit()
        elif resp.status_code == 404:
            print("The resource could not be found..")
            quit()
        else:
            unknownapierror(resp)

    if resp.status_code == 202:
        if debug:
            print (json.dumps(resp.json(), indent=4))
        print("User %s invited successfully." % (email))
    else:
        print("Unexpected result inviting user.")
        quit()

    return

def createaccesspolicy(subjects, roles, resources):
    # Create a policy

    parms = {
        "type": "access",
        "subjects": subjects,
        "roles": roles,
        "resources": resources
        }

    try:
        resp = requests.post(iam_endpoint + '/v1/policies', json=parms,
                             headers=iamToken, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        if resp.status_code == 400:
            print (parms)
            print("Policy input is invalid.")
            quit()
        elif resp.status_code == 401:
            print("Your access token is invalid or authentication of your token failed.")
            quit()
        elif resp.status_code == 403:
            print("Your access token is valid but does not have the necessary permissions to access this resource.")
            quit()
        elif resp.status_code == 404:
            print("The resource could not be found..")
            quit()
        elif resp.status_code == 409:
            print("A policy already exists for the given subject and resource. You can update that policy or delete it and create a new one.")
            return
        else:
            unknownapierror(resp)

    if resp.status_code == 201:
        if debug:
            print(json.dumps(resp.json(), indent=4))
    else:
        print("Unexpected result adding policy to existing user.")
        quit()
    return

def getaccessgroups():
    # Return list of all access groups
    accessGroups = []
    offset = 0
    limit = 100
    url = iam_endpoint + '/v2/groups?account_id=' + accountId + "&limit=" + str(limit) + "&offset=" + str(offset)
    while True:
        try:
            resp = requests.get(url, headers=iamToken,
                                timeout=30)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting:", errc)
            quit()
        except requests.exceptions.Timeout as errt:
            print("Timeout Error:", errt)
            quit()
        except requests.exceptions.HTTPError as errb:
            if resp.status_code == 401:
                print("Your access token is invalid or authentication of your token failed.")
                quit()
            elif resp.status_code == 403:
                print("Your access token is valid but does not have the necessary permissions to access this resource.")
                quit()
            else:
                unknownapierror(resp)

        if resp.status_code == 200:
            accessGroups = accessGroups + json.loads(resp.content)["groups"]
            if "next" in json.loads(resp.content):
                url = json.loads(resp.content)["next"]["href"]
            else:
                break
        else:
            print("Unexpected error getting user list, error code = %s." % (resp.status_code))
            quit()

    return accessGroups

def createaccessgroup(groupName, groupDescription):
    # Create an access group

    parms = {
        "name": groupName,
        "description": groupDescription
        }

    try:
        resp = requests.post(iam_endpoint + '/v2/groups?account_id=' + accountId, json=parms,
                             headers=iamToken, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        if resp.status_code == 400:
            print (parms)
            print("Bad Request")
            quit()
        elif resp.status_code == 401:
            print("Your access token is invalid or authentication of your token failed.")
            quit()
        elif resp.status_code == 403:
            print("Your access token is valid but does not have the necessary permissions to access this resource.")
            quit()
        else:
            unknownapierror(resp)

    if resp.status_code == 201:
        accessGroupId = resp.json()["id"]
        if debug:
            print(json.dumps(resp.json(), indent=3))
    else:
        print("Unexpected result creating access group.")
        quit()
    return accessGroupId

def getaccessgroupid(accessGroupName):
    # Get access group id
    accessGroup = list(filter(lambda accessGroup: accessGroup['name'] == accessGroupName, accessGroups))

    if len(accessGroup) > 0:
        accessGroupId = accessGroup[0]['id']
    else:
        accessGroupId = None

    return accessGroupId

def addmemberstoaccessgroups(accessGroupId, iamId):
    # Add members to access group
    parms = {
        "members": [
            {"iam_id": iamId, "type": "user"}
        ]
    }

    try:
        resp = requests.put(iam_endpoint + '/v2/groups/' + accessGroupId + "/members", json=parms,
                             headers=iamToken, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        quit()
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        quit()
    except requests.exceptions.HTTPError as errb:
        if resp.status_code == 400:
            print("Bad input")
            quit()
        if resp.status_code == 401:
            print("Your access token is invalid or authentication of your token failed.")
            quit()
        elif resp.status_code == 403:
            print("Your access token is valid but does not have the necessary permissions to access this resource.")
            quit()
        elif resp.status_code == 404:
            print("The access group could not be found..")
            quit()
        else:
            unknownapierror(resp)

    if resp.status_code == 207:
        if debug:
            print(json.dumps(resp.json(), indent=4))
        print("iamId %s added to access-group-id %s as member." % (iamId, accessGroupId))
    else:
        print("Unexpected result inviting user.")
        quit()

    return

def unknownapierror(resp):
    ################################################
    ## Handle Unknown RESPONSE CODE errors
    ################################################

    if resp.status_code >= 200 and resp.status_code < 300:
        print("Successful response, but unknown or unexpected response.")
        print("Response Code: %s" % (resp.status_code))
        print("Request Method: %s" % (resp.request.method))
        print("Request URL: %s" % (resp.request.url))
        print("Response: %s" % (resp.content))
        quit()

    if resp.status_code >= 300 and resp.status_code < 400:
        print("Your request was redirected resulting in an unknown or unexpected response.")
        print("Response Code: %s" % (resp.status_code))
        print("Request Method: %s" % (resp.request.method))
        print("Request URL: %s" % (resp.request.url))
        quit()

    if resp.status_code >= 400 and resp.status_code < 500:
        print("Unsuccessful response with an unexpected error code.")
        print("Response Code: %s" % (resp.status_code))
        print("Request Method: %s" % (resp.request.method))
        print("Request URL: %s" % (resp.request.url))
        print("Error Data: %s" % (json.loads(resp.content)['errors']))
        quit()

    return

def createadminaccesspolicy():
    #################################
    # Create Admin Access Group Policy
    #################################
    print("Creating policies for %s access-group." % (adminAccessGroupName))

    subjects = [
        {"attributes": [{"name": "access_group_id", "value": adminAccessGroupId}]}]

    roles = [{"role_id": "crn:v1:bluemix:public:iam::::role:Viewer"}]

    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceType",
                    "operator": "stringEquals",
                    "value": "resource-group"
                },
                {
                    "name": "resource",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                }
            ]
        }
    ]

    createaccesspolicy(subjects, roles, resources)

    print()

    print("Creating access-group policy for kms service.")
    roles = [
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Viewer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Operator"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Editor"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Administrator"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::serviceRole:Reader"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::serviceRole:Writer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::serviceRole:Manager"
        }
    ]
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "kms"
                }
            ]
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group policy for cloud-object-storage service.")

    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "cloud-object-storage"
                }
            ],
        }
    ]

    createaccesspolicy(subjects, roles, resources)
    print("Creating access-group policy for schematics service.")
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": defaultResourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "schematics"
                }
            ],
        }
    ]
    createaccesspolicy(subjects, roles, resources)
    print("Creating access-group policy for containers-kubernetes service.")
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "containers-kubernetes"
                }
            ],
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group %s policy for iam-groups service." % (adminAccessGroupName))
    roles = [
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Viewer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Operator"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Editor"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Administrator"
        }
    ]
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "iam-groups"
                },
                {
                    "name": "resource",
                    "operator": "stringEquals",
                    "value": adminAccessGroupId
                }
            ]
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group %s policy for iam-groups service." % (userAccessGroupName))
    roles = [
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Viewer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Operator"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Editor"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Administrator"
        }
    ]
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "iam-groups"
                },
                {
                    "name": "resource",
                    "operator": "stringEquals",
                    "value": userAccessGroupId
                }
            ]
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group policy for user-management service.")
    roles = [
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Viewer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Operator"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Editor"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Administrator"
        }
    ]
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "user-management"
                }
            ]
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    return

def createuseraccesspolicy():
    #################################
    # Create user Access Group Policy
    #################################
    print("Creating policies for %s access-group." % (userAccessGroupName))

    subjects = [
        {"attributes": [{"name": "access_group_id", "value": userAccessGroupId}]}]

    roles = [{"role_id": "crn:v1:bluemix:public:iam::::role:Viewer"}]

    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceType",
                    "operator": "stringEquals",
                    "value": "resource-group"
                },
                {
                    "name": "resource",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                }
            ]
        }
    ]

    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group policy for kms service.")
    roles = [
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Viewer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::role:Editor"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::serviceRole:Reader"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::serviceRole:Writer"
        },
        {
            "role_id": "crn:v1:bluemix:public:iam::::serviceRole:Manager"
        }
    ]
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "kms"
                }
            ]
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group policy for cloud-object-storage service.")

    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "cloud-object-storage"
                }
            ],
        }
    ]

    createaccesspolicy(subjects, roles, resources)

    print("Creating access-group policy for containers-kubernetes service.")
    resources = [
        {
            "attributes": [
                {
                    "name": "accountId",
                    "operator": "stringEquals",
                    "value": accountId
                },
                {
                    "name": "resourceGroupId",
                    "operator": "stringEquals",
                    "value": resourceGroupId
                },
                {
                    "name": "serviceName",
                    "operator": "stringEquals",
                    "value": "containers-kubernetes"
                }
            ],
        }
    ]
    createaccesspolicy(subjects, roles, resources)

    return

#####################################################
# MAIN PROGRAM
#####################################################

#####################################
# Set Global Variables
#####################################

resource_controller_endpoint = "https://resource-controller.cloud.ibm.com"
user_management_endpoint = "https://user-management.cloud.ibm.com"
iam_endpoint = "https://iam.cloud.ibm.com"

#####################################
# Get Arguments
#####################################

parser = argparse.ArgumentParser(description="Create resource-group.")
parser.add_argument("resourceGroup", help="Resource Group Name to be created." )
parser.add_argument("email", help="Email of user to invite to administer resource-group.")
parser.add_argument("-k", "--apiKey", default=os.environ.get('IC_API_KEY', None), help="IBM Cloud APIKey")
parser.add_argument("-a", "--accountid", default= "7a24585774d8b3c897d0c9b47ac48461", help="Account to create resource-group in")
parser.add_argument("-d", "--debug", action='store_true' ,default = False)

args = parser.parse_args()

if args.resourceGroup == None:
    print("You must specify a resource group name to be created.")
    quit()
else:
    resourceGroupName = args.resourceGroup

if args.email == None:
    print("You must specify an email to become administrator of the resource group.")
    quit()
else:
    email = args.email

debug = args.debug
apiKey = args.apiKey
accountId = args.accountid
iamToken = getiamtoken()


# Get list of resource groups that exist, and create group if it hasn't previously been created
print ("Retrieving existing resource-groups.")
resourceGroups = getresourcegroups()
if debug:
    print (json.dumps(resourceGroups,indent=3))

resourceGroupId = getresourcegroupid(resourceGroupName)

if resourceGroupId == None:
    resourceGroupId = createresourcegroup(resourceGroupName)
else:
    print ("resource-group %s (%s) already exists." % (resourceGroupName,resourceGroupId))

defaultResourceGroupId, defaultResourceGroupName = getdefaultresourcegroupid()
if defaultResourceGroupId == None:
    print ("Error.  No default resource group exists.")
    quit()
else:
    print ("Default resource-group %s (%s) exists." % (defaultResourceGroupName, defaultResourceGroupId))

## Get list of users, and invite user if not already a member of this account

print ("Retrieving existing users.")
users = getusers()
if debug:
    print (json.dumps(users, indent=3))

userId, userIamId, userState = getuserid(email)

if userId == None:
    print ("User does not already exist in account, inviting user.")
    inviteuserid(email, resourceGroupId)
    # refresh users & get newly invited user
    users = getusers()
    if debug:
        print(json.dumps(users, indent=3))
    userId, userIamId, userState = getuserid(email)

else:
    print ("User %s (%s) exists with IAM id %s in State = %s." % (email, userId, userIamId, userState) )
    # Add policy to be Admin of resource group
    subjects = [{ "attributes": [{"name": "iam_id","value": userIamId}]}]
    roles = [ { "role_id": "crn:v1:bluemix:public:iam::::role:Administrator"}]
    resources =  [{
            "attributes": [
                {"name": "accountId", "value": accountId},
                {"name": "resourceGroupId","value": resourceGroupId}
            ]}]
    createaccesspolicy(subjects, roles,resources)

#################################
# Get all access Groups
#################################
accessGroups = getaccessgroups()

#################################
#Create Admin Access Group
#################################

adminAccessGroupName = resourceGroupName + "-admins"
adminAccessGroupDescription = "Admin access group for resource-group " + resourceGroupName
adminAccessGroupId = getaccessgroupid(adminAccessGroupName)
if adminAccessGroupId == None:
    # create Access Group
    adminAccessGroupId = createaccessgroup(adminAccessGroupName, adminAccessGroupDescription)
    print('access-group %s (%s) created.' % (adminAccessGroupName, adminAccessGroupId))
else:
    print ('access-group %s (%s) already exists.' % (adminAccessGroupName, adminAccessGroupId))

#################################
# Create User Access Group
#################################

userAccessGroupName = resourceGroupName + "-users"
userAccessGroupDescription = "User access group for resource-group " + resourceGroupName
userAccessGroupId = getaccessgroupid(userAccessGroupName)
if userAccessGroupId == None:
    # create User Group
    userAccessGroupId = createaccessgroup(userAccessGroupName, userAccessGroupDescription)
    print('access-group %s (%s) created.' % (userAccessGroupName, userAccessGroupId))
else:
    print('access-group %s (%s) already exists.' % (userAccessGroupName, userAccessGroupId))

#################################
# Add Admin to both access groups
#################################

addmemberstoaccessgroups(adminAccessGroupId, userIamId)
addmemberstoaccessgroups(userAccessGroupId, userIamId)

#################################
# Create admin access policy
#################################
createadminaccesspolicy()

#################################
# Create user access policy
#################################
createuseraccesspolicy()

print ("Finished setting up resource-group, access-groups, and access for user %s." %(email))