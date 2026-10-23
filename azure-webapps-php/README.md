# Inventario de Azure Web Apps con PHP

Genera un Excel con **solo las Web Apps y slots que tienen PHP configurado en ARM**, y evalúa su **exposición pública directa según la configuración de red**. No incluye APIM ni Function Apps. Es un inventario de solo lectura: no despliega, reinicia, ejecuta comandos en las aplicaciones ni modifica permisos.

## Permisos y preparación

**Global Administrator de Microsoft Entra no concede automáticamente acceso a las suscripciones de Azure.** Para este script basta **Reader de Azure RBAC** sobre las suscripciones/grupos de recursos que quieras revisar. Si utilizas PIM, activa previamente el rol de lectura correspondiente. El script no activa roles, no eleva acceso y no solicita credenciales en el código.

Usa Azure Cloud Shell en modo **Bash**, o un equipo con **Python 3.10+ y Azure CLI**. El inventario se limita al tenant y a las suscripciones visibles para la sesión de Azure CLI.

```bash
git clone https://github.com/AlixerVolkov/Codex.git
cd Codex/azure-webapps-php
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

En Cloud Shell utiliza la sesión ya iniciada. En tu equipo, inicia sesión si es necesario:

```bash
az login --tenant "ID-DEL-TENANT"
az account list --all --query "[?state=='Enabled'].{Nombre:name,ID:id}" -o table
```

No envíes tokens, contraseñas ni archivos de credenciales por chat.

## Ejecutar

Todas las suscripciones habilitadas visibles, incluidos los slots:

```bash
python inventory.py --output "webapps_php.xlsx"
```

Una o varias suscripciones concretas:

```bash
python inventory.py \
  --subscriptions "11111111-1111-1111-1111-111111111111" "22222222-2222-2222-2222-222222222222" \
  --output "webapps_php_seleccion.xlsx"
```

Los UUID del ejemplo son ficticios: sustitúyelos por los tuyos. Para omitir slots, añade `--no-slots`. Los slots se revisan incluso cuando su aplicación principal usa otra tecnología. `--workers 4` limita la concurrencia y `--timeout 60` fija el tiempo máximo por comando de Azure CLI. Los archivos existentes no se sobrescriben.

Por defecto, una imagen personalizada no se presenta como PHP instalado. Opcionalmente:

```bash
python inventory.py --include-container-hints --output "webapps_php_con_indicios.xlsx"
```

Esto añade imágenes cuyo nombre sugiere PHP, marcadas **«Indicio de imagen; NO confirmado»**. No se descargan imágenes ni se accede al registro. Una imagen de nombre genérico puede contener PHP y no ser detectable por ARM; se documenta en `Incidencias`. Este script no inventaría PHP instalado pero oculto dentro de cualquier contenedor, ejecutable o filesystem.

## Interpretar el Excel

- **WebApps PHP**: recursos filtrados, runtime configurado, versión o rama, evidencia, exposición, motivo, estado de ejecución, restricciones y private endpoints.
- **Reglas acceso**: reglas de la aplicación principal con prioridad, acción, CIDR/service tag, subnet y nombres de cabeceras condicionadas. SCM/Kudu se excluye de esta evaluación.
- **Incidencias**: permisos insuficientes, lecturas fallidas y contenedores que no se pueden inspeccionar. Un recurso no legible **no se interpreta como «sin PHP»**.
- **Cobertura**: alcance enumerado por suscripción y si la enumeración fue completa.
- **Resumen**: totales, clasificación y limitaciones. Un informe vacío no demuestra ausencia de PHP si hay incidencias o faltan suscripciones.

La columna **Exposición pública configurada** utiliza:

| Valor | Significado |
|---|---|
| **Sí** | Endpoint predeterminado público y una familia IP abierta a orígenes públicos sin restricciones. |
| **Restringida** | Endpoint público sujeto a CIDR, service tags o condiciones de cabecera. **No equivale a privado.** |
| **No** | PNA deshabilitado, ASE interno para Web o ACL sin orígenes públicos permitidos identificados. Puede seguir habiendo acceso privado o una ruta indirecta. |
| **Indeterminada** | Faltan lecturas o hay reglas/configuraciones que no permiten una clasificación fiable. |

Se respetan las prioridades y el comportamiento predeterminado de las restricciones. No se decide la exposición solo por tener un hostname `azurewebsites.net`, `httpsOnly`, una integración VNet o un private endpoint. Un private endpoint no anula `publicNetworkAccess=Enabled`. Con la propiedad sin establecer, se aplica el comportamiento documentado según exista o no un private endpoint. Un App Service Environment con ILB para Web no se considera directamente público.

**No es una prueba de conectividad desde Internet.** El script no hace peticiones a las aplicaciones, no evalúa rutas indirectas por Front Door/Application Gateway/APIM, NSG/UDR, WAF, Easy Auth ni la autenticación propia de la aplicación. Los service tags y cabeceras se tratan conservadoramente; no se consultan rangos actuales de cada tag. Las aplicaciones detenidas conservan su clasificación de configuración y su estado `Stopped`; no se afirma que estén sirviendo tráfico.

**«PHP configurado» no confirma la versión del proceso ejecutándose.** Azure puede exponer solo una rama como `8.2`; esto no permite decidir si están corregidas CVE-2026-109618/109619. Tampoco se inspeccionan paquetes ni parches del proveedor.

No se leen App Settings, connection strings, credenciales de publicación ni secretos de Key Vault. Los nombres de recursos se exportan como texto de Excel para evitar fórmulas inesperadas.

### Códigos de salida

- `0`: informe generado sin incidencias registradas en el alcance seleccionado.
- `2`: informe generado con cobertura parcial o límites pendientes; revisa `Incidencias` y `Cobertura`.
- `1`: error que impidió completar el informe, como sesión inexistente, dependencia ausente o ninguna suscripción visible.

Si una plataforma de automatización trata `2` como fallo, conserva el Excel producido: contiene las lecturas que sí se pudieron completar.

## Descargar desde Cloud Shell

Usa **Manage files → Download** en Cloud Shell e indica la ruta de `webapps_php.xlsx`. El inventario se genera en tu entorno: **no se sube automáticamente a GitHub**.

## Validación local del script

```bash
python -m unittest discover -s tests -v
```

Las pruebas utilizan respuestas Azure ficticias y generan un Excel temporal; no requieren acceso a tu tenant. Cubren prioridades de ACL, CIDR solapados, IPv6, service tags, private endpoints, ASE, slots, lectura denegada, paginación y exportación sin secretos/fórmulas.

## Referencias oficiales

- [Restricciones de acceso y comportamiento de publicNetworkAccess](https://learn.microsoft.com/azure/app-service/overview-access-restrictions)
- [GET de configuración de Web Apps](https://learn.microsoft.com/rest/api/appservice/web-apps/get-configuration?view=rest-appservice-2024-11-01)
- [Listado de Web Apps](https://learn.microsoft.com/rest/api/appservice/web-apps/list?view=rest-appservice-2024-11-01)
- [Listado de slots](https://learn.microsoft.com/rest/api/appservice/web-apps/list-slots?view=rest-appservice-2024-11-01)
- [Diferencia entre roles de Microsoft Entra y Azure RBAC](https://learn.microsoft.com/azure/role-based-access-control/rbac-and-directory-admin-roles)
