import pandas as pd
import http
from requests.auth import HTTPBasicAuth
import requests
import json
import datetime

class IDMConn(object):

    IDMBasicUser=None
    IDMBasicPass=None
    IDMWebUser=None
    IDMWebPass=None
    IDMBaseUrl=None
    IDMTokenExpires=None
    IDMToken=None
    IDMRefreshToken=None
    IDMLogin='/osp/a/idm/auth/oauth2/grant'
    IDMLogout='/osp/a/idm/auth/app/logout'
    IDMRoleSearch='/IDMProv/rest/catalog/roles/listV2'
    IDMGetRole='/IDMProv/rest/catalog/roles/roleV2'
    IDMAddRole='/IDMProv/rest/catalog/roles'
    IDMRoleContainer='/IDMProv/rest/access/containers/container'
    IDMRoleCategory='/IDMProv/rest/catalog/roleCategories'

    def __init__(self, IDMBaseUrl, IDMBasicUser, IDMBasicPass, IDMWebUser, IDMWebPass):
        self.IDMBaseUrl = IDMBaseUrl
        self.IDMBasicUser = IDMBasicUser
        self.IDMBasicPass = IDMBasicPass
        self.IDMWebUser = IDMWebUser
        self.IDMWebPass = IDMWebPass

    def Login(self):
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
                # self.IDMTokenExpires = response.json().get('expires_in')
                expiredIn = response.json().get('expires_in')
                currTime = datetime.datetime.now()
                self.IDMTokenExpires = currTime + datetime.timedelta(seconds=expiredIn)
                print('currTime: ', currTime)
                print('IDMTokenExpires: ', self.IDMTokenExpires)
                return True
        return False
    
    def RefreshToken(self):
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
    
    def getRolesCategories(self, MaxSearch=500):
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
        if( self.IDMToken == None ):
            raise ValueError('Not Loged In')
        
        currTime = datetime.datetime.now()
        if self.IDMTokenExpires <= currTime:
            self.RefreshToken()


        searchUrl = self.IDMBaseUrl + self.IDMRoleSearch + '?sortOrder=asc&sortBy=name&size=' + str(MaxSearch) + '&q=' + RoleName
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.IDMToken
        }

        response = requests.get(searchUrl, headers=headers, verify=False)
        if(response.status_code == 200):
            # total
            if ( response.json().get('total') > 0 ):
                return response.json().get('roles')
        return []
            
    def createRole(self, RoleID: str, RoleName: str, RoleDesc: str, RoleCategory: list[str] = [], RoleLevel = 10, RoleCont: str = '' ):
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
        role['description'] = RoleDesc
        role['level'] = RoleLevel

        locNames = []
        locEn = {}
        locEn['locale'] = 'en'
        locEn['name'] = RoleName
        locNames.append(locEn)
        locEs = {}
        locEs['locale'] = 'es'
        locEs['name'] = RoleName
        locNames.append(locEs)
        role['localizedNames'] = locNames

        locDesc = []
        locEnD = {}
        locEnD['locale'] = 'en'
        locEnD['desc'] = RoleDesc
        locDesc.append(locEnD)
        locEsD = {}
        locEsD['locale'] = 'es'
        locEsD['desc'] = RoleDesc
        locDesc.append(locEsD)
        role['localizedDescriptions'] = locDesc

        catsIDM = self.getRolesCategories()

        roleCat = []
        for cat in RoleCategory:
            for catIDM in catsIDM:
                if catIDM['name'] == cat:
                    roleCat.append(catIDM)
            
        role['categories'] = roleCat

        if RoleCont != '':
            contsIDM = self.getRolesContainers(RoleLevel)
            contIDM = ''
            for cont in contsIDM:
                if cont['name'] == RoleCont:
                    contIDM = cont['dn']
                    
            if contIDM != '':
                role['subContainer'] = contIDM
        

        roleOwners = []
        role['owners'] = roleOwners
        role['status'] = 50
        role['approvalRequired'] = False
        role['revokeRequired'] = False

        addRoleUrl = self.IDMBaseUrl + self.IDMAddRole
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.IDMToken
        }
        role_json = json.dumps(role)
        print(role_json)
        response = requests.post(addRoleUrl, headers=headers, verify=False, data=role_json)
        if(response.status_code == 200):
            return response.json()
        else:
            raise ValueError('Algo salio mal', response.text)
        
        
