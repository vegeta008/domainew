# domained

Herramienta de enumeracion de subdominios pensada para flujos de reconocimiento en bug bounty y ejercicios de seguridad ofensiva. Automatiza la descarga de wordlists, la ejecucion de utilidades de terceros, la correlacion de resultados y la generacion de insumos reutilizables (listas de alcance, objetivos para EyeWitness y hosts validados HTTP/HTTPS).

> **Aviso:** domained ejecuta reconocimiento activo. Solo debe usarse sobre objetivos para los que tengas autorizacion expresa.

## Caracteristicas clave
- Orquesta herramientas probadas: Sublist3r, Knockpy, enumall, SubFinder, Amass, Subbrute + massdns y listas de Jason Haddix/SecLists.
- Puede integrar APIs de Shodan y SecurityTrails para enriquecer los resultados.
- Consolida, ordena y deduplica subdominios antes de exportarlos a multiples formatos (`*-unique.txt`, `scope.txt`, `*-urls.txt`).
- Genera wordlists derivadas (`*-extensions.txt`) y, si `httpx-toolkit` esta disponible, valida superficies HTTP/HTTPS.
- Dispara un webhook de DragonJAR para flujos externos y prepara listas para EyeWitness (incluyendo puertos alternos).
- Soporta notificaciones por Pushover o correo Gmail cuando el proceso concluye.
- Incluye instalador (`--install`/`--upgrade`) que clona dependencias en `./bin` y prepara resolvers/wordlists.

## Requisitos
- Distribucion GNU/Linux basada en Debian o Kali (recomendado) con Python 3.8 o superior.
- Paquetes del sistema: `libldns-dev`, `golang`, `git`, `make`.
- Dependencias Python: `pip install -r Requirements.txt`.
- Opcional:
  - `httpx-toolkit` en el `PATH` para la fase de validacion HTTP.
  - Credenciales API de Shodan y/o SecurityTrails.
  - Cuenta de Pushover o Gmail para avisos.

## Instalacion y actualizacion
```bash
git clone https://github.com/<tu-organizacion>/domained.git
cd domained
python3 domained.py --install      # o --upgrade para renovar dependencias
pip install -r Requirements.txt
```

El instalador clona los repositorios externos en `./bin`, compila massdns y descarga los wordlists necesarios. Tambien copia `resolvers.txt` a la raiz del proyecto.

## Configuracion opcional
- `ext/apicfg.ini`: habilita las secciones `[Shodan]` y/o `[SecurityTrails]`, define `enable = True` y agrega tu `api_key`.
- `ext/notifycfg.ini`: configura Pushover (`token`, `user`, `device`) o Gmail (`user`, `password`) y habilita la seccion correspondiente con `enable = True`.
- Ajusta `resolvers.txt` si deseas usar resolvers propios durante la fase de bruteforce.

## Uso basico
```bash
python3 domained.py -d ejemplo.com [opciones]
```

| Opcion | Resumen |
| ------ | ------- |
| `-d, --domain` | Dominio objetivo (obligatorio para ejecutar recon). |
| `-b, --bruteforce` | Activa subbrute + massdns con el wordlist por defecto (SecLists). |
| `--bruteall` | Reemplaza el wordlist por `all.txt` de Jason Haddix (requiere `-b`). |
| `-s, --secure` | Limita la lista de EyeWitness a URLs HTTPS. |
| `-p, --ports` | Agrega puertos alternos (`8080`, `8443`) a la lista de EyeWitness. |
| `-q, --quick` | Ejecuta solo Amass, SubFinder y las APIs habilitadas. |
| `--fresh` | Elimina `./output` antes de comenzar. |
| `--notify` | Envia notificacion al terminar (usa `ext/notifycfg.ini`). |
| `--vpn` | Verifica conectividad a un VPN mediante https://ifconfig.co/json. |
| `--active` | Ejecuta EyeWitness en modo active scan. |
| `--noeyewitness` | Omite cualquier invocacion a EyeWitness. |
| `--knock-timeout` | Sobrescribe el timeout de Knockpy (segundos). |
| `--install`, `--upgrade` | Instala o actualiza dependencias y termina la ejecucion. |

### Escenarios frecuentes
- **Enumeracion estandar:** `python3 domained.py -d ejemplo.com` -> Sublist3r, enumall, Knockpy, Amass, SubFinder y APIs.
- **Recon rapido:** `python3 domained.py -d ejemplo.com --quick` -> Amass, SubFinder y APIs (sin bruteforce).
- **Bruteforce extendido:** `python3 domained.py -d ejemplo.com -b --bruteall` -> Incluye Subbrute + massdns con `all.txt`.
- **Recon con validacion y puertos alternos:** `python3 domained.py -d ejemplo.com -b -p --notify`.

## Flujo de trabajo
1. **Banner y limpieza**: advierte sobre residuos previos (`*.csv`, `*.lst`) y ofrece eliminarlos.
2. **Ejecucion de herramientas**:
   - Sublist3r (con modo brute opcional), enumall (requiere Python2), Knockpy, Amass y SubFinder.
   - Shodan y SecurityTrails si hay claves habilitadas.
   - Subbrute + massdns cuando se usa `-b` (y `--bruteall` ajusta el wordlist).
3. **Consolidacion**:
   - Cada fuente genera `output/<dominio>/<dominio>_<tool>.txt`.
   - `*-all.txt` concatena fuentes y `*-unique.txt` deduplica dominios validos.
   - Se genera `scope.txt` para integraciones externas.
4. **Objetivos HTTP/HTTPS**:
   - `*-urls.txt` lista URLs para EyeWitness, ajustando protocolo y puertos segun `-s`/`-p`.
   - Si EyeWitness esta disponible y no se indico `--noeyewitness`, el script lo invoca.
5. **Validacion con httpx-toolkit** (opcional):
   - Si `httpx-toolkit` esta en el `PATH`, se ejecuta sobre `scope.txt`.
   - Resultados crudos en `archivofprobe.txt` y hosts validados en `finalvalidado.txt`.
6. **Wordlist derivada**:
   - Descarga una plantilla de DragonJAR, reemplaza `FUZZ` por el prefijo del dominio y guarda `<dominio>-extensions.txt`.
7. **Webhook DragonJAR**:
   - Lanza `GET https://n8n.dragonjar.co/webhook/recon?d=<dominio>` para pipelines externos.
8. **Notificaciones**:
   - Envia avisos Pushover o Gmail si `--notify` esta presente y la configuracion es valida.

## Archivos generados
Todos los artefactos se guardan en `output/<dominio>/`. Destacan:
- `<dominio>_sublist3r.txt`, `_knock.txt`, `_enumall.lst`, `_massdns.txt`, `_amass.txt`, `_subfinder.txt`, `_shodan.txt`, `_securitytrails.txt`.
- `<dominio>-all.txt` (consolidado) y `<dominio>-unique.txt` (deduplicado).
- `<dominio>-urls.txt` (entrada para EyeWitness).
- `<dominio>-extensions.txt` (wordlist personalizada).
- `combinar.txt` y `sinduplicados.txt` (agregados auxiliares).
- `scope.txt` (lista global de hosts) ubicado en la raiz del proyecto.
- `archivofprobe.txt` y `finalvalidado.txt` cuando se activa `httpx-toolkit`.

## Integraciones externas
- **APIs**: se consultan sobre HTTPS con `requests`, respetando un timeout de 30 segundos. Respuestas no exitosas se registran y la ejecucion continua.
- **EyeWitness**: se invoca con `eyewitness -f <archivo> --no-prompt --web [--active-scan]`.
- **httpx-toolkit**: se ejecuta como `httpx-toolkit -l scope.txt -v -silent -probe -server -sc`.
- **Webhook DragonJAR**: pensado para activar pipelines externos; puedes deshabilitarlo comentando la llamada.

## Consejos de operacion
- Ejecuta `python3 domained.py --install` tras clonar el repositorio o cuando actualices herramientas externas.
- Si usas `--fresh`, se regenerara la carpeta `output/` y sus subdirectorios.
- Verifica que `python2` exista si quieres aprovechar enumall.
- Ajusta `--knock-timeout` en entornos con latencia alta para evitar fallos en Knockpy.
- Instala `httpx-toolkit` (https://github.com/projectdiscovery/httpx) para validar servicios antes de lanzar EyeWitness.

## Limitaciones y buenas practicas
- No soporta multiples dominios en una sola ejecucion.
- Requiere permisos de red y posiblemente un entorno con Go para compilar algunas herramientas.
- massdns y subbrute pueden generar muchas peticiones; respeta los limites de tus proveedores.
- La plantilla de extensiones usa el prefijo del dominio, por lo que dominios muy cortos pueden producir coincidencias ruidosas; revisa `*-extensions.txt` antes de reutilizarlo.

---

Si encuentras errores o quieres extender la compatibilidad con nuevas fuentes, envia un PR o abre un issue. Feliz hunting!
