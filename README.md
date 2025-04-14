## Requisitos:

* Python 3.13.2
* Librerias:
  * request (python -m pip install requests)
* Recomendados:
  * VSCode

## Instalación

```
pip install -i https://test.pypi.org/simple/ cnetiq-idm-client
```

## Actualización

```
pip install --upgrade -i https://test.pypi.org/simple/ cnetiq-idm-client
```

## Documentación de la API REST

[NetIQ: REST API Documentation](https://www.netiq.com/documentation/identity-manager-developer/rest-api-documentation/idmappsdoc/)

## Registrar un usuario como cliente OAUTH

En el archivo ***ism-configurations.properties***

```properties
com.netiq.<clientid>.clientID = <clientid>
com.netiq.<clientid>.clientPass = <clientpassword>
com.netiq.<clientid>.redirect.url = https://webapp.example.com/oauth.html
```

Para ofuscar la contraseña:

```bash
java -jar /opt/netiq/idm/apps/tomcat/lib/obscurity-*jar "secret"
```

```
com.netiq.<clientid>.clientPass._attr_obscurity = ENCRYPT
com.netiq.<clientid>.clientPass = <cmd-output>
```

[OpenText Community: Identity Applications REST API via curl and jq](https://community.opentext.com/cybersec/idm/w/tips/14597/identity-applications-and-osp-rest-api-via-curl-and-jq)

## Info

* ***config.ini*** - Archivo donde se pueden definir los parámetros de conexión si se requiere para ser leidos con la libreria configparser (Ex: Ejemplo de llamados.ipynb)
* ***idm.py*** - librería con la clase ***IDMConn*** que permite los llamados a las API REST

  * Autenticación

    * Login - ***Login***
    * Refresh token - ***RefreshToken***
    * Logout - ***Logout***
  * Usuario:

    * Búsqueda de usuarios - ***searchUser***
    * Obtener información del usuario - ***getUserByDN***
  * Recursos

    * Buscar recursos - ***searchResourceByName***
    * Obtener información del recurso - ***getResourceByID***
  * Entitlements

    * Obtener los drivers que tienen entitlements - ***getDriversWithEntitlements***
    * Obtener entitlements asociados a los drivers - ***getDriversEntitlements***
    * Obtener los valores asociados a un entitlement - ***getEntitlementValues***
  * Flujos

    * Buscar flujos de aprobación - ***searchApprovalProcess***
  * Roles

    * Obtener categorías disponibles - ***getRolesCategories***
    * Obtener contenedores disponibles - ***getRolesContainers***
    * Obtener información de un rol - ***getRoleByID***
    * Buscar roles - ***searchRoleByName***
    * Crear rol - ***createRole***
    * Eliminar rol - ***deleteRoleByID***
    * Actualizar nombre de un rol - ***updateRoleName***
    * Actualizar descripción de un rol - ***updateRoleDesc***
    * Actualizar nombre y descripción de un rol - ***updateRoleInfo***
    * Agregar dueños de un rol - ***addRoleOwners***
    * Retirar dueños de un rol - ***removeRoleOwners***
    * Asignar flujo de aprobación - ***setRoleApproval***
    * Obtener roles hijos - ***getChildRoles***
    * Asignar roles hijos - ***addChildRoles***
    * Retirar roles hijos - ***removeChildRoles***
    * Obtener roles padre - ***getParentRoles***
    * Asignar roles padre - ***addParentRoles***
    * Retirar roles padre - ***removeParentRoles***
    * Obtener miembros del rol - ***getRoleAssignments***
    * Asignar miembros a un rol (Usuarios) - ***assignRoleToUsers***
    * Retirar miembros a un rol (Usuarios) - ***removeRoleFromUsers***

## Como usarlo

### Buscar un rol

```
from cnetiq_idm_client import  IDMConn

idmConn = IDMConn('https://myidm.examlple.com', 'custom-clientid', 'custom-secret', 'uaadmin', 'uaadmin-pass', IDMDebug=True)

idmConn.Login()

print("idmConn: ",idmConn)
print("rper : ",repr(idmConn))

role = idmConn.findRoleByName("child*")
roleF = idmConn.getRoleByID(role[0]['id'])

idmConn.Logout()
```

```
from cnetiq_idm_client import  IDMConn

with IDMConn('https://myidm.examlple.com', 'custom-clientid', 'custom-secret', 'uaadmin', 'uaadmin-pass', IDMDebug=True) as idmConn:
  print("idmConn: ",idmConn)
  print("rper : ",repr(idmConn))

  role = idmConn.findRoleByName("child*")
  roleF = idmConn.getRoleByID(role[0]['id'])

```