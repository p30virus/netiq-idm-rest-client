## Requisitos:

* Python 3.13.2
* Librerias:
  * request (python -m pip install requests)

## Documentacion de la API REST

https://www.netiq.com/documentation/identity-manager-developer/rest-api-documentation/idmappsdoc/

## Registrar un usuario como cliente OAUTH

En el archivo ism-configurations.properties

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

https://community.opentext.com/cybersec/idm/w/tips/14597/identity-applications-and-osp-rest-api-via-curl-and-jq

## Info

* config.ini - Archivo donde se pueden definir los parametros de conexion si se requiere
* idm.py - libreria con la clase IDMConn que permite los llamados a las API Web
  * Autenticacion
    * Login
    * Refresh token
    * Logout
  * Usuario:
    * Busqueda de usuarios
    * Obtener informacion del usuario
  * Recursos
    * Buscar recursos
    * Obtener informacion del recurso
  * Entitlements
    * Obtener los drivers que tienene entitlements
    * Obtener entitlements asociados a los drivers
    * Obtener los valores asociados a un entitlement
  * Flujos
    * Buscar flujos de aprobacion
  * Roles
    * Obtener categorias disponibles
    * Obtner contenedores disponibles
    * Obtener informacion de un rol
    * Buscar roles
    * Crear rol
    * Actualizar Nombre de un rol
    * Actualizar Descripcion de un rol
    * Actualizar nombre y descripcion de un rol
    * Agregar dueños de un rol
    * Retirar dueños de un rol
    * Asignar flujo de aprobacion
    * Borrar rol
    * Obtener roles hijos
    * Asignar roles hijos
    * Retirar roles hijos
    * Obtener padre hijos
    * Asignar padre hijos
    * Retirar padre hijos
    * Obtener miembros del rol
    * Asignar miembros a un rol (Usuarios)
    * Retirar miembros a un rol (Usuarios)
