![Entry banner](http://i.imgur.com/2tHHsEr.png "Entry banner")
# Unathorized Password Reset via Email Reply (CVE-2017-8295)
## Ficha de vulnerabilidad
  %|% 
------- | -------
**CVE:** 	    | CVE-2017-8295
**Severidad:**      | Media 
**Vector**          | [(AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C)
**Descubierto por:**| Dawid Golunski (@dawid_golunski)
**Afecta a:**	    | Wordpress (core) <= 4.7.4 (c/Apache)
**Fuentes:**	    | https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
~		    | https://nvd.nist.gov/vuln/detail/CVE-2017-8295
~		    | https://www.exploit-db.com/exploits/41963/
**Exploit Disponible:** | Sí (Parcial) - [wp-cve-2017-8296.py](https://github.com/mdiazcl/cyberthreat/blob/master/exploits/wordpress/cve-2017-8296/wp-cve-2017-8296.py)
**Fecha Exposición:** | 03/mayo/2017

## Resumen a alto nivel
Como todo sitio que maneja cuentas de usuario, Wordpress tiene una funcionalidad para recuperar contraseña ubicada en 
```
[dominio]/wp-login.php?action=lostpassword
```
![Wordpress Login](http://i.imgur.com/AaluCiB.png "Wordpress Login")

En el campo es necesario indicar el nombre de usuario o el email de la contraseña que se desea recuperar. Una ingresado esos datos es enviado un correo electrónico con un enlace, el que contiene un código para reiniciar la contraseña. El correo es enviado desde la siguiente dirección:

```
From: wordpress@[dominio]
```

Sin embargo, el dominio ([dominio]) que utiliza wordpress para enviar el correo es obtenido desde una variable en particular, la cual puede ser escrita por el usuario (dependiendo del Web-server), por lo que se puede forzar que el correo llegue desde otro dominio ([dominio-atacante]), uno controlado por el atacante, y es acá donde se puede aprovechar la vulnerabilidad.

Por definición, cuando un correo no puede ser enviado (Por razones como que el destinatario no existe, la casilla llena o el servidor de correo no está disponible) el servidor intentará enviarlo de nuevo y notificará al emisor original que el correo está en cola y aún no ha podido ser enviado, y en algunos casos, enviará una copia del correo enviado.

### Contexto de ataque
Si el atacante engaña a Wordpress (utilizando el exploit) para que envíe el correo de recuperación de contraseña desde una dirección de correo que manejamos (ie. wordpress@dominio-atacante.com) y causamos una disrupción de servicio (vía DDoS o ataques locales si estamos en la misma red) el servidor no podrá enviar el correo al destinatario original y notificará a nuestra dirección (wordpress@dominio-atacante.com) el error, colocando una copia del correo que intentó enviar y así obteniendo el código necesario para reiniciar la contraseña y tomar control de la cuenta.

La dificultad del ataque está en generar la disrupción del servicio en el servidor de correo. Si el usuario utiliza servidores de correo robustos es bastante más complejo realizar este ataque.

La vulnerabilidad afecta a toda instalación de Wordpress a la fecha. No existe solución por parte del equipo de Wordpress, sin embargo en esta entrada se propone una mitigación consistente en realizar una pequeña configuración en el servidor web (ver sección técnica).

## Explicación Técnica
La vulnerabilidad, tal como explica el resumen de alto nivel reside en la forma en que Wordpress envía el correo de recuperar contraseña a un usuario en particular. Si se inspecciona el código ubicado en `wp-includes/pluggable.php`

```php
if ( !isset( $from_email ) ) {
        // Get the site domain and get rid of www.
        $sitename = strtolower($_SERVER['SERVER_NAME']);
        if ( substr( $sitename, 0, 4 ) == 'www.' ) {
                $sitename = substr( $sitename, 4 );
        }

        $from_email = 'wordpress@' . $sitename;
}
```

Es posible ver que la variable `$sitename` es inicializada utilizando la variable de servidor `$_SERVER['SERVER_NAME']`. Dependiendo del servidor web que se esté utilizando esta variable es tomada desde diversas fuentes. En el caso de Apache por ejemplo, la variable es obtenida desde la cabecera `Host: www.sitio.cl` que va dentro del request HTTP realizado al servidor y no desde el servidor mismo (A menos que se active la opción UseCanonicalName, apagada por defecto).

> With ***UseCanonicalName Off*** Apache httpd will form self-referential URLs **using the hostname and port supplied by the client**
> Fuente: https://httpd.apache.org/docs/2.4/mod/core.html#usecanonicalname

Se probó el caso utilizando `nginx+php_fpm` e independiente del valor de la cabecera Host el resultado es obtenido de su respectivo archivo de configuración, por lo que la vulnerabilidad solo podría ser explotada si el servidor es Apache.

Sin embargo, qué es lo que quiere decir esto? Que si el atacante forja una cabecerá `Host: dominio-atacante.cl` el correo de recuperación de contraseña será enviado **desde `wordpress@dominio-atacante.cl`**, hasta ahora, nada vulnerable más que el usuario al cual se está solicitando fraudulentamente la contraseña recibirá el correo desde una dirección desconocida, sin embargo ahí está el truco. Si al momento de solicitar la contraseña, forjamos una dirección de envio que manejamos y causamos una disrupción de servicio (vía un ataque DDoS o algún MiTM si tenemos control de la red) el correo rebotará a nuestra dirección (ya que el servidor destino no está disponible)! Enviándonos una copia del correo en sí.

### Escenarios de ataque
Para que esto funcione entonces necesitamos:
* Forjar la cabecera `Host:` con un dominio que manejamos
* Hacer que el correo enviado rebote de alguna forma.

Para que el corre rebote, el autor propone 4 técnicas distintas, desde la más facil a la mas compleja:
+ Llenar la bandeja de correo de la víctima superando su quota
+ Tomar control del servidor DNS que maneja los registros MX de la víctima
+ (dificil) En algunos casos, la casilla tiene habilitada la opción de 'auto-responder' por vacaciones, lo que nos rebotaría el correo.
+ Enviar repetidas veces la restauración de contraseña hasta que la víctima responda el correo exigiendo una explicación y "ojalá" adjunte la copia que enviamos

Como pueden ver, el ataque requiere cierta ingeniería social.

## Mitigación
### Prupuesta 1:
Editar en el archivo httpd.conf y habilitar el uso canónico de nombres `UseCanonicalName On`

### Propuesta 2:
Editar el archivo `wp-includes/pluggable.php` en la línea 331 editar:
```
Original: $from_email = 'wordpress@' . $sitename;
Modificado: $from_email = 'wordpress@tusitio.cl';
```
