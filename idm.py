import pandas as pd
import http
from requests.auth import HTTPBasicAuth
import requests
import json
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IDMConn(object):

#region vars
    """
    Base URL
    """
    IDMBaseUrl=None
        
    """
    Session
    """
    IDMBasicUser=None
    IDMBasicPass=None
    IDMWebUser=None
    IDMWebPass=None
    IDMTokenExpires=None
    IDMToken=None
    IDMRefreshToken=None
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
    IDMRoleAssignemets='/IDMProv/rest/catalog/roles/role/assignments/v2'

    """
    Approval
    """
    IDMApproval = '/IDMProv/rest/catalog/prds'

    """
    Users
    """
    IDMUserSearch='/IDMProv/rest/access/users/list'
    IDMGetUSer='/IDMProv/rest/access/users/details'


#endregion vars
    
    def __init__(self, IDMBaseUrl, IDMBasicUser, IDMBasicPass, IDMWebUser, IDMWebPass):
        """
        Create the connection
        """
        self.IDMBaseUrl = IDMBaseUrl
        self.IDMBasicUser = IDMBasicUser
        self.IDMBasicPass = IDMBasicPass
        self.IDMWebUser = IDMWebUser
        self.IDMWebPass = IDMWebPass

#region Sessions
    
    def Login(self):
        """
        Login to the service - must be manually called
        """
        loginUrl = self.IDMBaseUrl + self.IDMLogin
        auth = HTTPBasicAuth(self.IDMBasicUser, self.IDMBasicPass)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = 'grant_type=password&username=' + self.IDMWebUser + '&password=' + self.IDMWebPass
        response = requests.post(loginUrl, data=data, headers=headers, auth=auth, verify=False)
        if(response.status_code == 200):
            if (response.json().get('access_token')):
                self.IDMToken = response.json().get('access_token')
                self.IDMRefreshToken = response.json().get('refresh_token')
                expiredIn = response.json().get('expires_in')
                currTime = datetime.datetime.now()
                self.IDMTokenExpires = currTime + datetime.timedelta(seconds=expiredIn)
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
        auth = HTTPBasicAuth(self.IDMBasicUser, self.IDMBasicPass)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = 'grant_type=refresh_token&username=' + self.IDMWebUser + '&password=' + self.IDMWebPass + '&refresh_token=' + self.IDMRefreshToken
        response = requests.post(loginUrl, data=data, headers=headers, auth=auth, verify=False)
        if(response.status_code == 200):
            if (response.json().get('access_token')):
                self.IDMToken = response.json().get('access_token')
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
        response = requests.get(logoutUrl, headers=headers, verify=False)
        if(response.status_code == 200):
            self.IDMToken = None
            self.IDMRefreshToken = None
            return True
        return False
    
#endregion Sessions

#region Approval

    def getApprovalProcess(self, ApprovalName: str = '*', MaxSearch=10):
        """
        Get Role Approval(WF)
        """
        # ?q=*&size=5&nextIndex=1&processType=Role%20Approval
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        wfUrl = self.IDMBaseUrl + self.IDMApproval + '?size=' + str(MaxSearch) + '&processType=Role%20Approval&q=' + ApprovalName
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        
        response = requests.get(wfUrl, headers=headers, verify=False)
        if(response.status_code == 200):
            # total
            if ( response.json().get('requestDefs')):
                return response.json().get('requestDefs')
        return []

#endregion Provision

#region Roles

    def getRolesCategories(self, MaxSearch=500):
        """
        Get available role categories
        """
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        catUrl = self.IDMBaseUrl + self.IDMRoleCategory + '?q=*&size=' + str(MaxSearch)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(catUrl, headers=headers, verify=False)
        if(response.status_code == 200):
            # total
            if ( response.json().get('arraySize') > 0 ):
                return response.json().get('categories')
        return []
    
    
    def getRolesContainers(self, RoleLevel: int):
        """
        Get available role containers by level
        """
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
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
        if(response.status_code == 200):
            return response.json().get('subContainers')
        return
    

    def getRoleByID(self, RoleID: str):
        """
        Get role by ID or DN
        """
        if RoleID == '':
            raise ValueError('No es posible buscar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
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

        if(response.status_code == 200):
            # total
            if ( response.json().get('arraySize') > 0 ):
                role = response.json().get('roles')[0]
                return role
        return json.loads('{}')
    

    def findRoleByName(self, RoleName: str, MaxSearch=500):
        """
        Search role by Name or CN
        """
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        searchUrl = self.IDMBaseUrl + self.IDMRoleSearch + '?sortOrder=asc&sortBy=name&size=' + str(MaxSearch) + '&q=' + RoleName
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)
        if(response.status_code == 200):
            # total
            if ( response.json().get('total') > 0 ):
                return response.json().get('roles')
            
        return []
            
    
    def createRole(self, RoleID: str, RoleName: str, RoleDesc: str, RoleCategory: list[str] = [], RoleLevel: int = 10, RoleCont: str = '', locals: list[str] = [ "zh_CN", "pt", "fr", "ru", "ja", "zh_TW", "it", "da", "iw", "de", "es", "en", "nb", "sv", "cs", "nl", "pl" ] ):
        """
        Create a role
        """
        if(RoleID == '' or RoleName == '' or RoleDesc == '' ):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
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

        if(response.status_code == 200):
            return response.json()
        else:
            raise ValueError('Algo salio mal', response.text)


    def updateRoleName(self, RoleID: str, RoleName: str):
        """
        Update role name
        """
        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions']

        if(RoleID == '' or RoleName == '' ):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
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

        if(response.status_code == 200):
            if response.json().get('success') == 'true':
                return response.json().get('succeeded')
            else:
                raise ValueError('Algo salio mal', response.json())
        else:
            raise ValueError('Algo salio mal', response.text)


    def updateRoleDesc(self, RoleID: str, RoleDesc: str):
        """
        Update role description
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions']

        if(RoleID == '' or RoleDesc == '' ):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
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

        if(response.status_code == 200):
            if response.json().get('success') == 'true':
                return response.json().get('succeeded')
            else:
                raise ValueError('Algo salio mal', response.json())
        else:
            raise ValueError('Algo salio mal', response.text)


    def updateRoleInfo(self, RoleID: str, RoleName: str, RoleDesc: str):
        """
        Update role name and description
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions']

        if(RoleID == '' or RoleName == '' or RoleDesc == '' ):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
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

        if(response.status_code == 200):
            if response.json().get('success') == 'true':
                return response.json().get('succeeded')
            else:
                raise ValueError('Algo salio mal', response.json())
        else:
            raise ValueError('Algo salio mal', response.text)


    def addRoleOwners( self, RoleID: str, NewRoleOwnersID: list[str] = []):
        """
        Add Owners using users DN
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions', 'owners']

        if(RoleID == ''):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            RoleInfo[key] = oldRoleInfo[key]

        
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

        if(response.status_code == 200):
            if response.json().get('success') == 'true':
                return response.json().get('succeeded')
            else:
                raise ValueError('Algo salio mal', response.json())
        else:
            raise ValueError('Algo salio mal', response.text)
        

    def removeRoleOwners( self, RoleID: str, NewRoleOwnersID: list[str] = []):
        """
        Add Owners using users DN
        """

        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions', 'owners']

        if(RoleID == ''):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        RoleInfo = {}

        for key in keysToMantain:
            RoleInfo[key] = oldRoleInfo[key]

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

        if(response.status_code == 200):
            if response.json().get('success') == 'true':
                return response.json().get('succeeded')
            else:
                raise ValueError('Algo salio mal', response.json())
        else:
            raise ValueError('Algo salio mal', response.text)


    def setRoleApproval(self, RoleID: str, RoleApprovalName: str = None, RoleApprovalForRevoke: bool = False):
        keysToMantain = ['id', 'name', 'localizedNames', 'description', 'localizedDescriptions', 'owners', 'approvalIsStandard', 'approvalRequired', 'approvalRequestDef', 'approvalRequestDefName', 'revokeRequired']
        if(RoleID == ''):
            raise ValueError('los parametros no pueden ser cadenas vacias')
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        if RoleApprovalName == '' or RoleApprovalName == None:
            RoleApprovalForRevoke = False

        approvalWFID = ''

        if RoleApprovalName != '' and RoleApprovalName != None:
            approvalExist = self.getApprovalProcess(RoleApprovalName)
            if len(approvalExist) == 0:
                raise ValueError('No se encuentra el proceso de approvacion')
            found = False
            for item in approvalExist:
                if item['name'] == RoleApprovalName:
                    found = True
                    approvalWFID = item['id']
                    break
            if found == False:
                raise ValueError('No se encuentra el proceso de approvacion')

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

        if(response.status_code == 200):
            if response.json().get('success') == 'true':
                return response.json().get('succeeded')
            else:
                raise ValueError('Algo salio mal', response.json())
        else:
            raise ValueError('Algo salio mal', response.text)


    def deleteRoleByID(self, RoleID: str):
        """
        Delete role by ID or DN
        """
        if RoleID == '':
            raise ValueError('No es posible borrar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
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
        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                role = response.json().get('succeeded')
                return role
        return json.loads('{}')
    

    def getChildRoles(self, RoleID: str):
        """
        Get Child roles
        """
        if RoleID == '':
            raise ValueError('No es posible obtener un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise ValueError('Rol no encontrado')

        if RoleInfo['level'] == 10:
            raise ValueError('Imposible obtener roles hijos de un rol 10')
        
        childUrl = self.IDMBaseUrl + self.IDMListChildRoles + '?q=*&size=500'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role = {}
        role['id'] = RoleID
        role_json = json.dumps(role)
        response = requests.post(childUrl, headers=headers, verify=False, data=role_json)
        if(response.status_code == 200):
            # total
            if ( response.json().get('arraySize') > 0 ):
                childRoles = response.json().get('roles')
                return childRoles
        return []
    
        
    def addChildRoles(self, RoleID: str, NewChildRoles: list[str] = [], Comment: str = 'Default comment'):
        """
        Add Child roles
        """
        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 10:
            raise ValueError('Imposible asignar rol hijo a un rol 10')
        #requestDescription

        rolesToAdd = []
        for role in NewChildRoles:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 30:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToAdd.append(tmpRoleData)
    
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

        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                childRoles = response.json().get('succeeded')
                return childRoles
        return []

    
    def removeChildRoles(self, RoleID: str, ChildRolesToRemove: list[str] = [], Comment: str = 'Default comment'):
        """
        Remove Child roles
        """
        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 10:
            raise ValueError('Imposible asignar rol hijo a un rol 10')
        #requestDescription

        rolesToRemove = []
        for role in ChildRolesToRemove:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 30:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToRemove.append(tmpRoleData)
    
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

        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                childRoles = response.json().get('succeeded')
                return childRoles
        return []


    def getParentRoles(self, RoleID: str):
        """
        Get Parent roles
        """
        if RoleID == '':
            raise ValueError('No es posible obtener un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise ValueError('Rol no encontrado')

        if RoleInfo['level'] == 30:
            raise ValueError('Imposible obtener roles padre de un rol 30')
        
        childUrl = self.IDMBaseUrl + self.IDMListParentRoles + '?q=*&size=500'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role = {}
        role['id'] = RoleID
        role_json = json.dumps(role)
        response = requests.post(childUrl, headers=headers, verify=False, data=role_json)
        if(response.status_code == 200):
            # total
            if ( response.json().get('arraySize') > 0 ):
                childRoles = response.json().get('roles')
                return childRoles
        return []
    

    def addParentRoles(self, RoleID: str, NewParentRoles: list[str] = [], Comment: str = 'Default comment'):
        """
        Add Child roles
        """
        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 30:
            raise ValueError('Imposible asignar rol padre a un rol 30')
        #requestDescription

        rolesToAdd = []
        for role in NewParentRoles:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 10:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToAdd.append(tmpRoleData)
    
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
        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                parentRoles = response.json().get('succeeded')
                return parentRoles
        return []
    

    def removeParentRoles(self, RoleID: str, ParentRolesToRemove: list[str] = [], Comment: str = 'Default comment'):
        """
        Remove Child roles
        """
        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        oldRoleInfo = self.getRoleByID(RoleID)

        if oldRoleInfo['level'] == 30:
            raise ValueError('Imposible retirar rol padre a un rol 30')
        #requestDescription

        rolesToRemove = []
        for role in ParentRolesToRemove:
            tmpRole = self.getRoleByID(role)
            if tmpRole['level'] != 10:
                tmpRoleData = {}
                tmpRoleData['id'] = tmpRole['id']
                tmpRoleData['requestDescription'] = Comment
                rolesToRemove.append(tmpRoleData)
    
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
        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                parentRoles = response.json().get('succeeded')
                return parentRoles
        return []
    

    def getRoleAssignemets(self, RoleID: str):
        """
        Get Users assigned to a role
        """
        # 

        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise ValueError('Imposible obtener los usuarios de un rol que no existe')

        Role = {}
        Role['dn'] = RoleID

        assignementsURL = self.IDMBaseUrl + self.IDMRoleAssignemets + '?q=&sortOrder=asc&sortBy=name&size=250'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role_json = json.dumps(Role)
        response = requests.post(assignementsURL, headers=headers, verify=False, data=role_json)
        if(response.status_code == 200):
            # total
            if ( response.json().get('total') > 0 ):
                assigned = response.json().get('assignmentStatusList')
                return assigned
        return []


    def assignRoleToUsers(self, RoleID: str, UsersDn: list[str] = [], EffectiveDate: datetime.datetime = datetime.datetime.now(), EndDate: datetime.datetime = None , Comment: str = 'Default comment'):
        """
        Assign a role to users
        """

        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise ValueError('Imposible asignar usuarios a un rol que no existe')
        
        usersToAdd = []

        if len(UsersDn) == 0:
            raise ValueError('Debe indicar un set de usuarios')

        # recipientDn

        alreadyAssignedJson = self.getRoleAssignemets(RoleID)
        alreadyAssigned = []
        for tmpRole in alreadyAssignedJson:
            alreadyAssigned.append(tmpRole['recipientDn'])

        tmpUsrToAdd = []
        for usr in alreadyAssigned:
            if usr not in UsersDn:
                tmpUsrToAdd.append(usr)


        for user in tmpUsrToAdd:
            tmpUsr = self.getUserByDN(user)
            if 'dn' in tmpUsr:
                tmpUsrD = {}
                tmpUsrD['assignedToDn'] = tmpUsr['dn']
                tmpUsrD['subtype'] = 'user'
                usersToAdd.append(tmpUsrD)

        assignments = []
        assignment = {}
        assignment['id'] = RoleID
        assignment['assignmentToList'] = usersToAdd
        # assignment['effectiveDate'] = str(int(EffectiveDate.timestamp()))
        # if EndDate != None:
        #     if EffectiveDate < EndDate:
        #         assignment['expiryDate'] = str(int(EndDate.timestamp()))
        #     else:
        #         raise ValueError('la fecha de retiro debe ser mayor a la fecha de asignacion')
        
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
        print('response: ', response.text)
        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                assigned = response.json().get('succeeded')
                return assigned
        return []


    def removeRoleFromUsers(self, RoleID: str, UsersDn: list[str] = [], Comment: str = 'Default comment'):
        """
        Assign a role to users
        """

        if RoleID == '':
            raise ValueError('No es posible modificar un rol con id en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        RoleInfo = self.getRoleByID(RoleID)

        if 'id' not in RoleInfo:
            raise ValueError('Imposible asignar usuarios a un rol que no existe')
        
        usersToRemove = []

        if len(UsersDn) == 0:
            raise ValueError('Debe indicar un set de usuarios')
        

        alreadyAssignedJson = self.getRoleAssignemets(RoleID)
        alreadyAssigned = []
        for tmpRole in alreadyAssignedJson:
            alreadyAssigned.append(tmpRole['recipientDn'])

        tmpUsrToRem = []
        for usr in UsersDn:
            if usr in alreadyAssigned:
                tmpUsrToRem.append(usr)
        
        for user in tmpUsrToRem:
            tmpUsr = self.getUserByDN(user)
            if 'dn' in tmpUsr:
                tmpUsrD = {}
                tmpUsrD['assignedToDn'] = tmpUsr['dn']
                tmpUsrD['subtype'] = 'user'
                usersToRemove.append(tmpUsrD)

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
        print('response: ', response.text)
        if(response.status_code == 200):
            # total
            if ( response.json().get('success') == 'true' ):
                assigned = response.json().get('succeeded')
                return assigned
        return []

#endregion Roles

#region Users

    def findUserByCN(self, UserCN: str, MaxSearch=500):
        """
        Search users by the CN
        """
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()

        if UserCN == '':
            raise ValueError('Debe especificar un CN de usuario')
        
        #?q=deville&clientId=1&nextIndex=1&size=25&sortOrder=asc&sortBy=&searchAttr=FirstName,LastName,Email,TelephoneNumber,CN&advSearch=
        
        searchUrl = self.IDMBaseUrl + self.IDMUserSearch + '?sortOrder=asc&sortBy=name&searchAttr=CN&' + UserCN + '&size=' + str(MaxSearch) + '&advSearch='
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)

        if(response.status_code == 200):
            # total
            if ( response.json().get('totalSize') > 0 ):
                return response.json().get('usersList')
            
        return []


    def getUserByDN(self, UserDN: str):
        """
        get users by the DN
        """
        if UserDN == '':
            raise ValueError('No es posible buscar un usuario con dn en blanco')
        
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        searchUrl = self.IDMBaseUrl + self.IDMGetUSer + '?userDn=' + UserDN
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)

        if(response.status_code == 200):
            user = response.json()
            return user
        return json.loads('{}')

#endregion Users