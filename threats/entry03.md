![Entry banner](http://i.imgur.com/9uGULA3.png)

# Keylogger Presente en driver de audio Equipos HP (CVE-2017-5689)
---
## Ficha de vulnerabilidad
  %|%
------- | -------
**CVE:**            | CVE-2017-8360
**Severidad:**      | Media
**Vector**          | No Aplica
**Descubierto por:**| modzero (https://www.modzero.ch).
**Afecta a:**       | Equipos HP serie Elitebook, ProBook, ZBook, Elite [(Lista detallada)](https://github.com/mdiazcl/cyberthreat/blob/master/threats/entry03files/hp_affected_machines.md)
**Fuentes:**        | https://www.modzero.ch/modlog/archives/2017/05/11/en_keylogger_in_hewlett-packard_audio_driver/index.html
~                   | http://thehackernews.com/2017/05/hp-audio-driver-laptop-keylogger.html
~                   | https://security.stackexchange.com/questions/159219/whats-my-exposure-and-how-to-close-it-from-conexant-hd-audio-driver-package
**Exploit:** | No Aplica
**Fecha Exposición:** | 11/mayo/2017

## Resumen a alto nivel
---
La empresa de seguridad [modzero](https://www.modzero.ch/) descubrió la presencia de un Keylogger que viene instalado en  los equipos marca HP, en los controladores de Audio. Este programa se ejecuta de manera automática cuando se inicia el computador y comienza a generar un registro de todas las teclas que el usuario presiona, registrando contraseñas, conversaciones, emails, y todo aquello que el usuario teclee en el teclado (valga la redundancia).

Esto no es una vulnerabilidad per-se, ya que no es producto de alguna actividad maliciosa de un atacante o de alguna falla del sistema, si no más bien una mala implementación de software por parte de HP, la cual está de manera pre-instalada en dichos equipos.

El listado de los equipos vulnerables se encuentra en el siguiente enlace:
> [Listado de Máquinas HP afectadas](https://github.com/mdiazcl/cyberthreat/blob/master/threats/entry03files/hp_affected_machines.md)

La mitigación de esta vulnerabilidad es bastante trivial, incluso se puede automatizar la detección y eliminación de este software de manera automática.

### Contexto de ataque
Los escenarios en que esta amenaza concretarse en un incidente de seguridad es si un usuario tiene acceso al sistema de archivos (Disco duro) mediante otra vulnerabilidad o compartiendo la carpeta `Públic` presentes en el equipo.

Es importante destacar que el primer escenario es bastante complejo, depende de que existan otras vulnerabilidades, sin embargo el segun puede ser más común. Por defecto la carpeta Públic no se comparte pero es altamente probable que algún usuario la utilice para compartir archivos de manera pública en la red.

>**La amenaza que representa este comportamiento indeseado es suficiente para realizar acciones correctivas.**

### Contexto Latinoamericano
La presencia de equipos HP en la industria chilena es bastante amplia, lamentablemente no contamos con estadísticas duras sobre ella, sin embargo en múltiples auditorias de seguridad, los profesionales de Cyberthreat se han encontrado con el uso de equipos HP.

## Recomendación
Se recomienda revisar todos los equipos de la empresa, ya sea de manera automática y manual por la presencia de este software. En la sección técnica se especifican los detalles

# Explicación técnica
---
La empresa HP implementó un software en el controlador de audio para capturar las teclas especiales que se presionan en el computador, sin embargo por un "error de programación" (que áun no se sabe si fue intencional o no) el software quedó en modo debug capturando todas las teclas que se presionaban, especiales o no, escribiendo lo capturado en un directorio Público dentro del disco duro ubicado en `C:\Users\Public\MicTray.log`. Cada vez que el computador inicia sesión este archivo se reescribe.

El software encargado de realizar la captura de estas pulsaciones de teclado puede estar presente en dos formas dependiendo de la arquitectura:

```
C:\Windows\System32\MicTray64.exe
C:\Windows\System32\MicTray.exe
```

Si revisas y encuentras estos archivos es muy probable que el software haya estado registrando todas las pulsaciones de teclado y dejando todo registrado en:
```
C:\Users\Public\MicTray.log
```

Lamentablemente la dirección `C:\Users\Public\` son directorios de acceso global al sistema operativo, por lo que cualquier computador que esté siendo compartido puede ver el archivo del otro.

La ejecución de `MicTray64.exe` y `MicTray.exe` se realizaba gracias a un Schedule Tasks (tarea prograda) en Windows.

Se ha notificado a lo largo de internet que muchos encuentran el archivo `MicTray.log` vacio. Cuando esto ocurre simplemente basta con revisar que `MicTray64.exe` y `MicTray.exe` no estén presentes en el sistema para estar seguros.

### Explotación
Tan solo es necesario acceder a la ruta dónde MicTray.log está y revisar su contenido. No necesita ningúna permiso adicional para ello.

### Escenarios de ataque
No aplica

### Detección de la Amenaza
Para detectar si la amenaza está presente revisa si los archivos
```
C:\Windows\System32\MicTray64.exe
C:\Windows\System32\MicTray.exe
C:\Users\Public\MicTray.log
```
Están presentes en el sistema.

### Mitigación
Para mitigar esta vulnerabilidad tan solo basta con eliminar los archivos `MicTray64.exe` y `MicTray.exe` de la carpeta System32 y el registro de Log.
