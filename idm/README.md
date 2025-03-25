## Requisitos:

* Python 3.13.2
* Librerias:
  * request (python -m pip install requests)
* Recomendados:
  * VSCode

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

    * Login
    * Refresh token
    * Logout
  * Usuario:

    * Búsqueda de usuarios
    * Obtener información del usuario
  * Recursos

    * Buscar recursos
    * Obtener información del recurso
  * Entitlements

    * Obtener los drivers que tienene entitlements
    * Obtener entitlements asociados a los drivers
    * Obtener los valores asociados a un entitlement
  * Flujos

    * Buscar flujos de aprobación
  * Roles

    * Obtener categorías disponibles
    * Obtener contenedores disponibles
    * Obtener información de un rol
    * Buscar roles
    * Crear rol
    * Actualizar nombre de un rol
    * Actualizar descripción de un rol
    * Actualizar nombre y descripción de un rol
    * Agregar dueños de un rol
    * Retirar dueños de un rol
    * Asignar flujo de aprobación
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
