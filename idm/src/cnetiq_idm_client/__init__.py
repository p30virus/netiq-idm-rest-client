from warnings import deprecated
from requests.auth import HTTPBasicAuth
import requests
import json
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IDMConn(object):


#region vars
    """
    DEBUG
    """
    IDMDebug=False
    """
    Base URL
    """
    IDMBaseUrl=None
        
    """
    Session
    """
    IDMClientID=None
    IDMClientSecret=None
    IDMWebUser=None
    IDMWebPass=None
    IDMTokenExpires=None
    IDMToken=None
    IDMRefreshToken=None
    IDMOSPCookie=None
    IDMLogin='/osp/a/idm/auth/oauth2/grant'
    IDMLogout='/osp/a/idm/auth/app/logout'

    """
    Roles
    """
    IDMRoleSearch='/IDMProv/rest/catalog/roles/listV2'
    IDMGetRole='/IDMProv/rest/catalog/roles/roleV2'
    IDMAddRole='/IDMProv/rest/catalog/roles'
    IDMRoleContainer='/IDMProv/rest/access/containers/container'
    IDMRoleCategory='/IDMProv/rest/catalog/roleCategories'
    IDMUpdateRole='/IDMProv/rest/catalog/roles/roles'
    IDMDeleteRole='/IDMProv/rest/catalog/roles/role'
    IDMListChildRoles='/IDMProv/rest/catalog/roles/subRoles/list'
    IDMChildRoles='/IDMProv/rest/catalog/roles/subRoles'
    IDMListParentRoles='/IDMProv/rest/catalog/roles/parentRoles/list'
    IDMParentRoles='/IDMProv/rest/catalog/roles/parentRoles'
    IDMAssignRole='/IDMProv/rest/catalog/roles/role/assignments/assign'
    IDMRemoveRole='/IDMProv/rest/access/assignments/list'
    IDMRoleAssignments='/IDMProv/rest/catalog/roles/role/assignments/v2'

    """
    Approval
    """
    IDMApproval = '/IDMProv/rest/catalog/prds'

    """
    Users
    """
    IDMUserSearch='/IDMProv/rest/access/users/list'
    IDMGetUSer='/IDMProv/rest/access/users/details'

    """
    Resources
    """
    IDMResourceSearch='/IDMProv/rest/catalog/resources/listV2'
    IDMGetResource='/IDMProv/rest/catalog/resources/resourceV2'
    IDMDrivers='/IDMProv/rest/catalog/drivers'
    IDMDriversEntitlements='/IDMProv/rest/catalog/drivers/driver'
    IDMDriversEntitlementsValues='/IDMProv/rest/catalog/drivers/entitlementValues/listV2'
    

#endregion vars


    def __init__(self, IDMBaseUrl: str, IDMClientID: str, IDMClientSecret: str, IDMWebUser: str, IDMWebPass: str, IDMDebug: bool=False):
        """
        Create the connection
        """
        self.IDMBaseUrl = IDMBaseUrl
        self.IDMClientID = IDMClientID
        self.IDMClientSecret = IDMClientSecret
        self.IDMWebUser = IDMWebUser
        self.IDMWebPass = IDMWebPass
        self.IDMDebug = IDMDebug

    def __str__(self):
        if self.IDMToken == None:
            return f'Not logged in'
        else:
            return f'Logged in to {self.IDMBaseUrl} using {self.IDMClientID} and the user {self.IDMWebUser}'
        
    def __repr__(self):
        if self.IDMToken == None:
            return f'IDMConn(Not logged in)'
        else:
            return f'IDMConn(url={self.IDMBaseUrl}, ClientID={self.IDMClientID}, User={self.IDMWebUser}, Token={self.IDMToken}, RefreshToken={self.IDMRefreshToken}'
        
    def __enter__(self):
        self.Login()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.Logout()
        if exc_type:
            raise Exception('algo salio mal')
        return True


#region Sessions
    
    def Login(self):
        """
        Login to the service - must be manually called
        """
        loginUrl = self.IDMBaseUrl + self.IDMLogin
        auth = HTTPBasicAuth(self.IDMClientID, self.IDMClientSecret)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = 'grant_type=password&username=' + self.IDMWebUser + '&password=' + self.IDMWebPass
        response = requests.post(loginUrl, data=data, headers=headers, auth=auth, verify=False)
        if(response.status_code == 200):
            if ( 'access_token' in response.json() ):
                self.IDMToken = response.json().get('access_token')
                self.IDMRefreshToken = response.json().get('refresh_token')
                expiredIn = response.json().get('expires_in')
                currTime = datetime.datetime.now()
                self.IDMTokenExpires = currTime + datetime.timedelta(seconds=expiredIn)
                self.IDMOSPCookies = response.cookies.get_dict()
                if self.IDMDebug == True:
                    print('token: ', self.IDMToken)
                    print('cookies: ', self.IDMOSPCookies)
                return True
        return False
    
   
    def RefreshToken(self):
        """
        Refresh the token
        """
        if( self.IDMRefreshToken == None ):
            self.Logout()
            return False
        
        loginUrl = self.IDMBaseUrl + self.IDMLogin
        auth = HTTPBasicAuth(self.IDMClientID, self.IDMClientSecret)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = 'grant_type=refresh_token&username=' + self.IDMWebUser + '&password=' + self.IDMWebPass + '&refresh_token=' + self.IDMRefreshToken
        response = requests.post(loginUrl, data=data, headers=headers, auth=auth, verify=False, cookies=self.IDMOSPCookies)
        if(response.status_code == 200):
            if ( 'access_token' in response.json() ):
                self.IDMToken = response.json().get('access_token')
                self.IDMOSPCookies = response.cookies.get_dict()
                if self.IDMDebug == True:
                    print('token: ', self.IDMToken)
                    print('cookies: ', self.IDMOSPCookies)
                return True
        return False
    
    
    def Logout(self):
        """
        Logout from the service - must be manually called
        """
        if( self.IDMToken == None ):
            self.IDMToken = None
            self.IDMRefreshToken = None
            return True
        
        logoutUrl = self.IDMBaseUrl + self.IDMLogout
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        response = requests.get(logoutUrl, headers=headers, verify=False, cookies=self.IDMOSPCookies)
        
        if self.IDMDebug == True:
            print('Logout response: ', response.status_code)

        if(response.status_code == 200):
            self.IDMToken = None
            self.IDMRefreshToken = None
            self.IDMOSPCookies = None
            return True
        return False
    
#endregion Sessions


#region Approval

    def searchApprovalProcess(self, ApprovalName: str = '*', MaxSearch=10):
        """
        Get Role Approval(WF)
        """
        # ?q=*&size=5&nextIndex=1&processType=Role%20Approval
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        wfUrl = self.IDMBaseUrl + self.IDMApproval + '?size=' + str(MaxSearch) + '&processType=Role%20Approval&q=' + ApprovalName
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        
        response = requests.get(wfUrl, headers=headers, verify=False)
        if self.IDMDebug == True:
            print('URL: ', wfUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'requestDefs' in response.json() ):
                return response.json().get('requestDefs')
        return []

#endregion Provision


#region Roles

    def getRolesCategories(self, MaxSearch=500):
        """
        Get available role categories
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        catUrl = self.IDMBaseUrl + self.IDMRoleCategory + '?q=*&size=' + str(MaxSearch)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(catUrl, headers=headers, verify=False)

        if self.IDMDebug == True:
            print('URL: ', catUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'categories' in response.json() ):
                return response.json().get('categories')
        return []
    
    
    def getRolesContainers(self, RoleLevel: int):
        """
        Get available role containers by level
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        contUrl = self.IDMBaseUrl + self.IDMRoleContainer

        level = {}
        level['level'] = RoleLevel
        level_json = json.dumps(level)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        response = requests.post(contUrl, headers=headers, verify=False, data=level_json)

        if self.IDMDebug == True:
            print('URL: ', contUrl)
            print('json: ', level_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            return response.json().get('subContainers')
        return
    

    def getRoleByID(self, RoleID: str):
        """
        Get role by ID or DN
        """
        if RoleID == '':
            raise Exception('No es posible buscar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        searchUrl = self.IDMBaseUrl + self.IDMGetRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        roles = {}
        role = {}
        role['id'] = RoleID
        roles['roles'] = role
        roles_json = json.dumps(roles)
        response = requests.post(searchUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'roles' in response.json() ):
                role = response.json().get('roles')[0]
                return role
        return json.loads('{}')
    
    @deprecated('Renombrada a searchRoleByName')
    def findRoleByName(self, RoleName: str='*', MaxSearch=500):
        return self.searchResourceByName(RoleName, MaxSearch)

    def searchRoleByName(self, RoleName: str='*', MaxSearch=500):
        """
        Search role by Name or CN
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        searchUrl = self.IDMBaseUrl + self.IDMRoleSearch + '?sortOrder=asc&sortBy=name&size=' + str(MaxSearch) + '&q=' + RoleName
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'roles' in response.json() ):
                return response.json().get('roles')
            
        return []
            
    
    def createRole(self, RoleID: str, RoleName: str, RoleDesc: str, RoleCategory: list[str] = [], RoleLevel: int = 10, RoleCont: str = '', locals: list[str] = [ "zh_CN", "pt", "fr", "ru", "ja", "zh_TW", "it", "da", "iw", "de", "es", "en", "nb", "sv", "cs", "nl", "pl" ] ):
        """
        Create a role
        """
        if(RoleID == '' or RoleName == '' or RoleDesc == '' ):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        role = {}
        role['id'] = RoleID
        role['name'] = RoleName
        
        locNames = []
        for locale in locals:
            loc = {}
            loc['locale'] = locale
            loc['name'] = RoleName
            locNames.append(loc)

        role['localizedNames'] = locNames

        role['description'] = RoleDesc
        
        locDesc = []

        for locale in locals:
            loc = {}
            loc['locale'] = locale
            loc['desc'] = RoleName
            locDesc.append(loc)

        role['localizedDescriptions'] = locDesc

        catsIDM = self.getRolesCategories()

        roleCat = []
        for cat in RoleCategory:
            for catIDM in catsIDM:
                if catIDM['name'] == cat:
                    roleCat.append(catIDM)
            
        role['categories'] = roleCat

        contIDM = ''
        if RoleCont != '':
            contsIDM = self.getRolesContainers(RoleLevel)
            
            for cont in contsIDM:
                if cont['name'] == RoleCont:
                    contIDM = cont['dn']
                    
        if contIDM != '':    
            role['subContainer'] = contIDM        

        roleOwners = []
        role['owners'] = roleOwners
        role['level'] = RoleLevel
        role['status'] = 50
        role['approvalRequired'] = False
        role['revokeRequired'] = False

        addRoleUrl = self.IDMBaseUrl + self.IDMAddRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role_json = json.dumps(role)
        

        response = requests.post(addRoleUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', addRoleUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            return response.json()
        else:
            raise Exception('Algo salio mal', response.text)


    def updateRoleName(self, RoleID: str, RoleName: str):
        """
        Update role name
        """
        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions']

        if(RoleID == '' or RoleName == '' ):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            if key in oldRoleInfo:
                RoleInfo[key] = oldRoleInfo[key]


        RoleInfo['name'] = RoleName

        for i, locData in enumerate(RoleInfo['localizedNames']):
            RoleInfo['localizedNames'][i]['name'] = RoleName

        modRoleUrl = self.IDMBaseUrl + self.IDMUpdateRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        roles = {}
        roles['roles'] = []
        roles['roles'].append(RoleInfo)
        roles_json = json.dumps(roles)

        response = requests.put(modRoleUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', modRoleUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            if ( 'succeeded' in response.json() ):
                return response.json().get('succeeded')
            else:
                raise Exception('Algo salio mal', response.json())
        else:
            raise Exception('Algo salio mal', response.text)


    def updateRoleDesc(self, RoleID: str, RoleDesc: str):
        """
        Update role description
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions']

        if(RoleID == '' or RoleDesc == '' ):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            if key in oldRoleInfo:
                RoleInfo[key] = oldRoleInfo[key]


        RoleInfo['description'] = RoleDesc

        for i, locData in enumerate(RoleInfo['localizedDescriptions']):
            RoleInfo['localizedDescriptions'][i]['desc'] = RoleDesc

        modRoleUrl = self.IDMBaseUrl + self.IDMUpdateRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        roles = {}
        roles['roles'] = []
        roles['roles'].append(RoleInfo)
        roles_json = json.dumps(roles)

        response = requests.put(modRoleUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', modRoleUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            if ( 'succeeded' in response.json() ):
                return response.json().get('succeeded')
            else:
                raise Exception('Algo salio mal', response.json())
        else:
            raise Exception('Algo salio mal', response.text)


    def updateRoleInfo(self, RoleID: str, RoleName: str, RoleDesc: str):
        """
        Update role name and description
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions']

        if(RoleID == '' or RoleName == '' or RoleDesc == '' ):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            if key in oldRoleInfo:
                RoleInfo[key] = oldRoleInfo[key]


        RoleInfo['name'] = RoleName

        for i, locData in enumerate(RoleInfo['localizedNames']):
            RoleInfo['localizedNames'][i]['name'] = RoleName

        RoleInfo['description'] = RoleDesc

        for i, locData in enumerate(RoleInfo['localizedDescriptions']):
            RoleInfo['localizedDescriptions'][i]['desc'] = RoleDesc

        modRoleUrl = self.IDMBaseUrl + self.IDMUpdateRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        roles = {}
        roles['roles'] = []
        roles['roles'].append(RoleInfo)
        roles_json = json.dumps(roles)

        response = requests.put(modRoleUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', modRoleUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            if ( 'succeeded' in response.json() ):
                return response.json().get('succeeded')
            else:
                raise Exception('Algo salio mal', response.json())
        else:
            raise Exception('Algo salio mal', response.text)


    def addRoleOwners( self, RoleID: str, NewRoleOwnersID: list[str] = []):
        """
        Add Owners using users DN
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions', 'owners']

        if(RoleID == ''):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            if key in oldRoleInfo:
                RoleInfo[key] = oldRoleInfo[key]

        if 'owners' not in RoleInfo:
            RoleInfo['owners'] = []
        
        for owner in NewRoleOwnersID:
            ownerExist = self.getUserByDN(owner)
            if 'dn' in ownerExist:
                ownerTmp = {}
                ownerTmp['id'] = ownerExist['dn']
                ownerTmp['name'] = ownerExist['fullName']
                ownerTmp['type'] = "user"
                RoleInfo['owners'].append(ownerTmp)



        
        modRoleUrl = self.IDMBaseUrl + self.IDMUpdateRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        roles = {}
        roles['roles'] = []
        roles['roles'].append(RoleInfo)
        roles_json = json.dumps(roles)

        response = requests.put(modRoleUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', modRoleUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            if ( 'succeeded' in response.json() ):
                return response.json().get('succeeded')
            else:
                raise Exception('Algo salio mal', response.json())
        else:
            raise Exception('Algo salio mal', response.text)
        

    def removeRoleOwners( self, RoleID: str, NewRoleOwnersID: list[str] = []):
        """
        Add Owners using users DN
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions', 'owners']

        if(RoleID == ''):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            if key in oldRoleInfo:
                RoleInfo[key] = oldRoleInfo[key]

        if 'owners' not in RoleInfo:
            RoleInfo['owners'] = []

        currOwners = RoleInfo['owners']
        newOwners = []
        
        for owner in currOwners:
            if owner['id'] not in NewRoleOwnersID:
                newOwners.append(owner)
        
        RoleInfo['owners'] = newOwners
        
        roles = {}
        roles['roles'] = []
        roles['roles'].append(RoleInfo)
        roles_json = json.dumps(roles)

        modRoleUrl = self.IDMBaseUrl + self.IDMUpdateRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.put(modRoleUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', modRoleUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            if ( 'succeeded' in response.json() ):
                return response.json().get('succeeded')
            else:
                raise Exception('Algo salio mal', response.json())
        else:
            raise Exception('Algo salio mal', response.text)


    def setRoleApproval(self, RoleID: str, RoleApprovalName: str = None, RoleApprovalForRevoke: bool = False):
        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions', 'owners', 'approvalIsStandard', 'approvalRequired', 'approvalRequestDef', 'approvalRequestDefName', 'revokeRequired']
        if(RoleID == ''):
            raise Exception('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        if RoleApprovalName == '' or RoleApprovalName == None:
            RoleApprovalForRevoke = False

        approvalWFID = ''

        if RoleApprovalName != '' and RoleApprovalName != None:
            approvalExist = self.searchApprovalProcess(RoleApprovalName)
            if len(approvalExist) == 0:
                raise Exception('No se encuentra el proceso de aprobacion')
            found = False
            for item in approvalExist:
                if item['name'] == RoleApprovalName:
                    found = True
                    approvalWFID = item['id']
                    break
            if found == False:
                raise Exception('No se encuentra el proceso de aprobacion')

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            if key in oldRoleInfo:
                RoleInfo[key] = oldRoleInfo[key]


        if RoleApprovalName != '' and RoleApprovalName != None:
            RoleInfo['approvalIsStandard'] = False
            RoleInfo['approvalRequired'] = True
        else:
            RoleInfo['approvalIsStandard'] = False
            RoleInfo['approvalRequired'] = False

        RoleInfo['revokeRequired'] = RoleApprovalForRevoke
        RoleInfo['approvalRequestDef'] = approvalWFID
        RoleInfo['approvalRequestDefName'] = RoleApprovalName

        roles = {}
        roles['roles'] = []
        roles['roles'].append(RoleInfo)
        roles_json = json.dumps(roles)

        modRoleUrl = self.IDMBaseUrl + self.IDMUpdateRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.put(modRoleUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', modRoleUrl)
            print('json: ', roles_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            if ( 'succeeded' in response.json() ):
                return response.json().get('succeeded')
            else:
                raise Exception('Algo salio mal', response.json())
        else:
            raise Exception('Algo salio mal', response.text)


    def deleteRoleByID(self, RoleID: str):
        """
        Delete role by ID or DN
        """
        if RoleID == '':
            raise Exception('No es posible borrar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        deleteUrl = self.IDMBaseUrl + self.IDMDeleteRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        roles = {}
        role = {}
        role['id'] = RoleID
        roles['roles'] = role
        roles_json = json.dumps(roles)

        response = requests.delete(deleteUrl, headers=headers, verify=False, data=roles_json)

        if self.IDMDebug == True:
            print('URL: ', deleteUrl)
            print('json: ', roles_json)
            print('response: ', response.text)


        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                role = response.json().get('succeeded')
                return role
        return json.loads('{}')
    

    def getChildRoles(self, RoleID: str):
        """
        Get Child roles
        """
        if RoleID == '':
            raise Exception('No es posible obtener un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise Exception('Rol no encontrado')

        if RoleInfo['level'] == 10:
            raise Exception('Imposible obtener roles hijos de un rol 10')
        
        childUrl = self.IDMBaseUrl + self.IDMListChildRoles + '?q=*&size=500'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role = {}
        role['id'] = RoleID
        role_json = json.dumps(role)
        response = requests.post(childUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', childUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'roles' in response.json() ):
                childRoles = response.json().get('roles')
                return childRoles
        return []
    
        
    def addChildRoles(self, RoleID: str, NewChildRoles: list[str] = [], Comment: str = 'Default comment'):
        """
        Add Child roles
        """
        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 10:
            raise Exception('Imposible asignar rol hijo a un rol 10')
        #requestDescription

        rolesToAdd = []
        for role in NewChildRoles:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 30:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToAdd.append(tmpRoleData)

        if len(rolesToAdd) == 0:
            raise Exception('Está intentando asignar roles que no existen')   
        
        role = {}
        role['roleId'] = RoleID
        role['subRoles'] = rolesToAdd

        childUrl = self.IDMBaseUrl + self.IDMChildRoles
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        role_json = json.dumps(role)
        response = requests.post(childUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', childUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                childRoles = response.json().get('succeeded')
                return childRoles
        return []

    
    def removeChildRoles(self, RoleID: str, ChildRolesToRemove: list[str] = [], Comment: str = 'Default comment'):
        """
        Remove Child roles
        """
        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 10:
            raise Exception('Imposible asignar rol hijo a un rol 10')
        #requestDescription

        rolesToRemove = []
        for role in ChildRolesToRemove:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 30:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToRemove.append(tmpRoleData)

        if len(rolesToRemove) == 0:
            raise Exception('Está intentando asignar roles que no existen')   
    
        role = {}
        role['roleId'] = RoleID
        role['subRoles'] = rolesToRemove

        childUrl = self.IDMBaseUrl + self.IDMChildRoles
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        role_json = json.dumps(role)
        response = requests.delete(childUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', childUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                childRoles = response.json().get('succeeded')
                return childRoles
        return []


    def getParentRoles(self, RoleID: str):
        """
        Get Parent roles
        """
        if RoleID == '':
            raise Exception('No es posible obtener un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise Exception('Rol no encontrado')

        if RoleInfo['level'] == 30:
            raise Exception('Imposible obtener roles padre de un rol 30')
        
        childUrl = self.IDMBaseUrl + self.IDMListParentRoles + '?q=*&size=500'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role = {}
        role['id'] = RoleID
        role_json = json.dumps(role)
        response = requests.post(childUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', childUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'roles' in response.json() ):
                childRoles = response.json().get('roles')
                return childRoles
        return []
    

    def addParentRoles(self, RoleID: str, NewParentRoles: list[str] = [], Comment: str = 'Default comment'):
        """
        Add Child roles
        """
        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 30:
            raise Exception('Imposible asignar rol padre a un rol 30')
        #requestDescription

        rolesToAdd = []
        for role in NewParentRoles:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 10:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToAdd.append(tmpRoleData)

        if len(rolesToAdd) == 0:
            raise Exception('Está intentando asignar roles que no existen')    
    
        role = {}
        role['roleId'] = RoleID
        role['parentRoles'] = rolesToAdd

        childUrl = self.IDMBaseUrl + self.IDMParentRoles
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        role_json = json.dumps(role)
        response = requests.post(childUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', childUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                parentRoles = response.json().get('succeeded')
                return parentRoles
        return []
    

    def removeParentRoles(self, RoleID: str, ParentRolesToRemove: list[str] = [], Comment: str = 'Default comment'):
        """
        Remove Child roles
        """
        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 30:
            raise Exception('Imposible retirar rol padre a un rol 30')
        #requestDescription

        rolesToRemove = []
        for role in ParentRolesToRemove:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 10:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToRemove.append(tmpRoleData)
    
        if len(rolesToRemove) == 0:
            raise Exception('Está intentando asignar roles que no existen')
        
        role = {}
        role['roleId'] = RoleID
        role['parentRoles'] = rolesToRemove

        childUrl = self.IDMBaseUrl + self.IDMParentRoles
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        role_json = json.dumps(role)
        response = requests.delete(childUrl, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', childUrl)
            print('json: ', role_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                parentRoles = response.json().get('succeeded')
                return parentRoles
        return []
    

    def getRoleAssignments(self, RoleID: str):
        """
        Get Users assigned to a role
        """
        # 

        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise Exception('Imposible obtener los usuarios de un rol que no existe')

        Role = {}
        Role['dn'] = RoleID

        assignementsURL = self.IDMBaseUrl + self.IDMRoleAssignments + '?q=&sortOrder=asc&sortBy=name&size=250'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role_json = json.dumps(Role)
        response = requests.post(assignementsURL, headers=headers, verify=False, data=role_json)

        if self.IDMDebug == True:
            print('URL: ', assignementsURL)
            print('json: ', role_json)
            print('response: ', response.text)


        if(response.status_code == 200):
            # total
            if ( 'assignmentStatusList' in response.json() ):
                assigned = response.json().get('assignmentStatusList')
                return assigned
        return []


    def assignRoleToUsers(self, RoleID: str, UsersDn: list[str] = [], EffectiveDate: datetime.datetime = datetime.datetime.now(), EndDate: datetime.datetime = None , Comment: str = 'Default comment'):
        """
        Assign a role to users
        """

        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise Exception('Imposible asignar usuarios a un rol que no existe')

        if len(UsersDn) == 0:
            raise Exception('Debe indicar un set de usuarios')

        # recipientDn

        alreadyAssignedJson = self.getRoleAssignments(RoleID)
        alreadyAssigned = []
        for tmpRole in alreadyAssignedJson:
            alreadyAssigned.append(tmpRole['recipientDn'])

        tmpUsrToAddArr = []

        for tmpUsrToAdd in UsersDn:
            if tmpUsrToAdd not in alreadyAssigned:
                tmpUsrToAddArr.append(tmpUsrToAdd)

        usersToAdd = []

        for user in tmpUsrToAddArr:
            tmpUsr = self.getUserByDN(user)
            if 'dn' in tmpUsr:
                tmpUsrD = {}
                tmpUsrD['assignedToDn'] = tmpUsr['dn']
                tmpUsrD['subtype'] = 'user'
                usersToAdd.append(tmpUsrD)

        if len(usersToAdd) == 0:
            raise Exception('Los usuarios que intenta asignar no existen')
        
        assignments = []
        assignment = {}
        assignment['id'] = RoleID
        assignment['assignmentToList'] = usersToAdd

        assignment['effectiveDate'] = str(int(EffectiveDate.timestamp() * 1000))
        if EndDate != None:
            if EffectiveDate < EndDate:
                assignment['expiryDate'] = str(int(EndDate.timestamp() * 1000))
            else:
                raise Exception('la fecha de retiro debe ser mayor a la fecha de asignacion')
        
        assignments.append(assignment)
        reqData = {}
        reqData['assignments'] = assignments
        reqData['reason'] = Comment
        reqData_json = json.dumps(reqData)

        assignUrl = self.IDMBaseUrl + self.IDMAssignRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.post(assignUrl, headers=headers, verify=False, data=reqData_json)

        if self.IDMDebug == True:
            print('URL: ', assignUrl)
            print('json: ', reqData_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                assigned = response.json().get('succeeded')
                return assigned
        return []


    def removeRoleFromUsers(self, RoleID: str, UsersDn: list[str] = [], Comment: str = 'Default comment'):
        """
        Remove role from users
        """

        if RoleID == '':
            raise Exception('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise Exception('Imposible retirar usuarios a un rol que no existe')

        if len(UsersDn) == 0:
            raise Exception('Debe indicar un set de usuarios')
        

        alreadyAssignedJson = self.getRoleAssignments(RoleID)
        alreadyAssigned = []
        for tmpRole in alreadyAssignedJson:
            alreadyAssigned.append(tmpRole['recipientDn'])


        tmpUsrToRmArr = []

        for tmpUsrToAdd in UsersDn:
            if tmpUsrToAdd in alreadyAssigned:
                tmpUsrToRmArr.append(tmpUsrToAdd)

        usersToRemove = []

        for user in tmpUsrToRmArr:
            tmpUsr = self.getUserByDN(user)
            if 'dn' in tmpUsr:
                tmpUsrD = {}
                tmpUsrD['assignedToDn'] = tmpUsr['dn']
                tmpUsrD['subtype'] = 'user'
                usersToRemove.append(tmpUsrD)

        if len(usersToRemove) == 0:
            raise Exception('Los usuarios que intenta retirar no existen o no tienen asignado el rol')

        assignments = []
        assignment = {}
        assignment['id'] = RoleID
        assignment['entityType'] = "role"
        assignment['assignmentToList'] = usersToRemove
        
        assignments.append(assignment)
        reqData = {}
        reqData['assignments'] = assignments
        reqData['reason'] = Comment
        reqData_json = json.dumps(reqData)

        assignUrl = self.IDMBaseUrl + self.IDMRemoveRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.delete(assignUrl, headers=headers, verify=False, data=reqData_json)

        if self.IDMDebug == True:
            print('URL: ', assignUrl)
            print('json: ', reqData_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'succeeded' in response.json() ):
                assigned = response.json().get('succeeded')
                return assigned
        return []

#endregion Roles


#region Users

    @deprecated('Renombrada a searchUser')
    def findUser(self, UserCN: str ='*', MaxSearch=500, FilterAttrs: list[str] = ['CN', 'FirstName', 'LastName', 'Email', 'TelephoneNumber']):
        return self.searchUser(UserCN, MaxSearch, FilterAttrs)

    def searchUser(self, UserCN: str ='*', MaxSearch=500, FilterAttrs: list[str] = ['CN', 'FirstName', 'LastName', 'Email', 'TelephoneNumber']):
        """
        Search users by the CN
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        if UserCN == '':
            raise Exception('Debe especificar un CN de usuario')
        
        attrs = 'CN'
        if len(FilterAttrs) > 1:
            attrs = ','.join(FilterAttrs)
        
        
        searchUrl = self.IDMBaseUrl + self.IDMUserSearch + '?q=' + UserCN + '&sortOrder=asc&sortBy=name&searchAttr=' + attrs + '&size=' + str(MaxSearch) + '&advSearch='
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        response = requests.get(searchUrl, headers=headers, verify=False)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'usersList' in response.json() ):
                return response.json().get('usersList')
            
        return []


    def getUserByDN(self, UserDN: str):
        """
        get users by the DN
        """
        if UserDN == '':
            raise Exception('No es posible buscar un usuario con dn en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        searchUrl = self.IDMBaseUrl + self.IDMGetUSer + '?userDn=' + UserDN
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            user = response.json()
            return user
        return json.loads('{}')

#endregion Users


#region Resources


    @deprecated('Renombrada a searchResourceByName')
    def findResourceByName(self, ResourceName: str='*', MaxSearch=500):
        return self.searchResourceByName(ResourceName, MaxSearch)

    def searchResourceByName(self, ResourceName: str='*', MaxSearch=500):
        """
        Search resource by Name
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()
        
        
        #/IDMProv/rest/catalog/resources/listV2

        searchUrl = self.IDMBaseUrl + self.IDMResourceSearch + '?sortOrder=asc&sortBy=name&size=' + str(MaxSearch) + '&q=' + ResourceName
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'resources' in response.json() ):
                return response.json().get('resources')
        return []
    
    def getResourceByID(self, ResourceID: str):
        """
        Get resource by ID or DN
        """
        if ResourceID == '':
            raise Exception('No es posible buscar un recurso con id en blanco')
        
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        #/IDMProv/rest/catalog/resources/resourceV2

        searchUrl = self.IDMBaseUrl + self.IDMGetResource
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        resources = {}
        resource = {}
        resource['id'] = ResourceID
        resources['resources'] = resource

        resources_json = json.dumps(resources)
        response = requests.post(searchUrl, headers=headers, verify=False, data=resources_json)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('resources_json: ', resources_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'resources' in response.json() ):
                role = response.json().get('resources')[0]
                return role
        return json.loads('{}')

#endregion Resources


#region Entitlements

    def getDriversWithEntitlements(self):
        """
        Get all the drivers with config entitlements
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        searchUrl = self.IDMBaseUrl + self.IDMDrivers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        
        response = requests.get(searchUrl, headers=headers, verify=False)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'drivers' in response.json() ):
                drivers = response.json().get('drivers')
                return drivers
        return json.loads('{}') 
    

    def getDriversEntitlements(self, DriverID: str='', ):
        """
        Get all the entitlements for a driver
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        if DriverID == '':
            raise Exception('No es posible driver con id en blanco')

        searchUrl = self.IDMBaseUrl + self.IDMDriversEntitlements
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        
        driver = {}
        driver['id'] = DriverID
        driver_json = json.dumps(driver)

        response = requests.post(searchUrl, headers=headers, verify=False, data=driver_json)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('driver_json: ', driver_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'entitlements' in response.json()):
                drivers = response.json().get('entitlements')
                return drivers
        return json.loads('{}') 


    def getEntitlementValues(self, EntitlemenID: str, Value: str = '*'):
        """
        Get entitlements avaliable values
        """
        if( self.IDMToken == None ):
            raise Exception('Not Logged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        if EntitlemenID == '':
            raise Exception('No es posible buscar un entitlement con id en blanco')
        
        # IDMDriversEntitlementsValues
        

        searchUrl = self.IDMBaseUrl + self.IDMDriversEntitlementsValues + '?query=' + Value
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        
        ent = {}
        ent['id'] = EntitlemenID
        ent_json = json.dumps(ent)

        response = requests.post(searchUrl, headers=headers, verify=False, data=ent_json)

        if self.IDMDebug == True:
            print('URL: ', searchUrl)
            print('ent_json: ', ent_json)
            print('response: ', response.text)

        if(response.status_code == 200):
            # total
            if ( 'entitlementValues' in response.json()):
                drivers = response.json().get('entitlementValues')
                return drivers
        return json.loads('{}') 

#endregion Entitlements
