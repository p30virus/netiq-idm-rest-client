API DOCS

https://www.netiq.com/documentation/identity-manager-developer/rest-api-documentation/idmappsdoc/

Register OAUTH client

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
