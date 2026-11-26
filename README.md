# soc-monitor

Plataforma de monitoreo diario sin agente (agentless) y auditoría DevSecOps/SOC para infraestructura híbrida (~100 servidores Linux vía SSH/Paramiko y ~100 servidores Windows vía WinRM HTTPS/5986), diseñada para ejecutarse en **Rocky Linux 10** con **Python 3.12+**, **PostgreSQL 16**, **FastAPI**, **SQLAlchemy 2.0 + Alembic**, **WeasyPrint** y **SELinux en enforcing**.

---

## Arquitectura

```text
app/
  main.py                  # FastAPI + lifespan + APScheduler + CLI (--run-once)
  config.py                # Configuración con pydantic-settings (.env)
  database.py              # Engine SQLAlchemy 2.0 + SessionLocal
  security.py              # Fernet, Argon2id, JWT, HashiCorp Vault, Rate Limiter
  logging_config.py        # Logging estructurado JSON con redacción de secretos
  models/                  # ORM: hosts, host_groups, credentials_ref, baselines, check_results,
                           # findings, firewall_baseline, firewall_allowed_rules,
                           # admin_users_allowed, admin_users_current, admin_users_history,
                           # thresholds, audit_log, reports, scan_runs, system_users, app_settings
  collectors/              # linux_collector.py (Paramiko SSH), windows_collector.py (pywinrm HTTPS)
  discovery/               # baseline_service.py (descubrimiento v1, diff y aprobación)
  checks/                  # engine.py (filesystem, CPU, RAM/swap, servicios, logs, updates, drift)
  firewall/                # analyzer.py (puertos permitidos, 0.0.0.0/0, Any-to-Any, baseline)
  users/                   # admin_audit.py (admins no autorizados, >90d inactivos, pwd sin expirar)
  reporting/               # generator.py (HTML interactivo + PDF WeasyPrint + JSON para LLM)
  scheduler/               # runner.py (ThreadPoolExecutor con retries/timeouts + APScheduler)
  web/                     # Consola web FastAPI + Jinja2 + Tailwind CSS + RBAC + AuditLog
migrations/                # Migraciones Alembic
scripts/                   # install.sh, update.sh, backup.sh, setup_linux_target.sh, setup_windows_target.ps1
systemd/                   # soc-monitor.service, soc-monitor.timer, soc-monitor-scan.service
tests/                     # Pruebas pytest con 2 mocks Linux + 2 mocks Windows
```

---

## Instalación en Rocky Linux 10

1. Clonar el repositorio y ejecutar el instalador idempotente como `root`:
```bash
git clone <URL_REPO> /opt/soc-monitor
cd /opt/soc-monitor
chmod +x scripts/*.sh
sudo ./scripts/install.sh
```
El script `install.sh` realiza automáticamente:
- Instalación de dependencias del sistema (`python3.12`, `postgresql-server`, `pango`, `cairo`, `gdk-pixbuf2`, `firewalld`, `logrotate`, `policycoreutils-python-utils`).
- Creación del usuario de servicio `socmonitor` y directorios `/etc/soc-monitor`, `/var/lib/soc-monitor/{reports,backups}`, `/var/log/soc-monitor`.
- Inicialización de PostgreSQL 16 y creación de la base de datos `socmonitor`.
- Creación de `.venv`, instalación de `requirements.txt` y ejecución de `alembic upgrade head`.
- Generación de certificado TLS autofirmado (reemplazable por Let's Encrypt) y archivo `/etc/soc-monitor/.env` con clave `FERNET_KEY` y `JWT_SECRET`.
- Configuración de SELinux (`http_port_t` en puerto `8443` y `restorecon`) y apertura exclusiva del puerto `8443/tcp` en `firewalld`.
- Habilitación del servicio `soc-monitor.service`.

2. (Opcional) Si prefieres usar `systemd timer` en lugar del scheduler interno `APScheduler`:
```bash
sudo systemctl enable --now soc-monitor.timer
```

---

## Configuración Inicial y Onboarding de los Primeros 5 Servidores

1. Accede a la consola web en `https://<IP_SERVIDOR>:8443` con las credenciales iniciales definidas en `/etc/soc-monitor/.env` (`socadmin` / `ChangeMe!SocAdmin2026`) y cambia la contraseña desde **Usuarios del Sistema**.
2. Prepara las cuentas de solo lectura en los servidores destino:
   - **Linux**: ejecuta `scripts/setup_linux_target.sh '<llave_publica_ssh>'` en cada servidor Linux para crear el usuario `socmon_ro` con permisos `sudo` estrictamente de lectura.
   - **Windows**: ejecuta `scripts/setup_windows_target.ps1 -Password '<Pass>'` en cada servidor Windows para crear `socmon_ro` (sin privilegios de Domain Admin) y habilitar WinRM HTTPS en el puerto `5986`.
3. En la consola web ve a **Grupos & Umbrales** y crea grupos (ej. `Web`, `BD`, `Windows-App`).
4. En **Inventario & Credenciales**:
   - Crea las credenciales (`SSH Private Key` para Linux, `WinRM NTLM` para Windows). Se cifran con **Fernet** antes de guardarse en PostgreSQL.
   - Agrega tus primeros 5 servidores (por ejemplo: 3 Linux y 2 Windows) asignándoles su grupo y credencial.
   - Haz clic en **Probar** en cada fila para validar conectividad SSH/WinRM.

---

## Ejecución Manual y Actualización

- **Escaneo manual**: desde el **Dashboard** o **Reportes**, haz clic en **Ejecutar Escaneo Ahora** (o por CLI: `/opt/soc-monitor/.venv/bin/python -m app.main --run-once`).
- **Actualización**:
```bash
sudo /opt/soc-monitor/scripts/update.sh
```
- **Backup diario de BD** (agregar a cron de `root`):
```cron
0 3 * * * RETENTION_DAYS=30 /opt/soc-monitor/scripts/backup.sh >> /var/log/soc-monitor/backup.log 2>&1
```

---

## Pruebas Automatizadas

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest -v
```

---

## Supuestos

1. **Conectividad y DNS**: El servidor central `soc-monitor` tiene conectividad de red hacia los puertos `22/tcp` (Linux) y `5986/tcp` (Windows WinRM HTTPS) de los ~200 hosts monitoreados.
2. **Certificados WinRM**: En entornos internos con certificados autofirmados en WinRM, se puede ajustar `WINRM_VERIFY_SSL=false` en `.env` mientras se despliega una PKI interna.
3. **Tailwind CSS**: La consola web carga Tailwind CSS vía CDN (`cdn.tailwindcss.com`) para evitar procesos de build con Node.js. En redes air-gapped se puede sustituir el `<script>` en `app/web/templates/base.html` por un CSS compilado estático en `app/web/static/`.
4. **WeasyPrint en pruebas locales**: La generación de PDF requiere librerías nativas de sistema (`pango`, `cairo`, `gdk-pixbuf2`), las cuales son instaladas automáticamente por `scripts/install.sh` en Rocky Linux 10. Si faltan en un entorno mínimo de desarrollo, el generador registra una advertencia y produce igualmente los reportes HTML y JSON sin abortar el escaneo.
5. **Escaneo diario a las 02:00**: Se configura por defecto a las `02:00 UTC` vía `APScheduler` (y se provee `systemd/soc-monitor.timer` como alternativa nativa).

---

## Lista de Verificación de Aceptación

1. **Verificar Descubrimiento y Baseline**:
   - Agrega un host Linux/Windows en `/inventory` y ejecuta un escaneo manual desde el Dashboard.
   - Verifica en `/baselines` que se creó la línea base `v1` (`approved_by: auto-discovery`).
2. **Verificar Escaneo Diario**:
   - Ejecuta `.venv/bin/python -m app.main --run-once` o espera al horario programado (`02:00`).
   - Confirma que `scan_runs` registra `status=completed` y que un host inalcanzable no detiene el escaneo de los demás.
3. **Verificar Cambio de Umbral en Consola Web**:
   - En `/groups`, configura `disk_pct` con `warning=75`, `critical=88` para un grupo.
   - Ejecuta un nuevo escaneo y valida que los hallazgos aplican el nuevo umbral sin reiniciar el servicio.
4. **Verificar Generación de Reportes (HTML, PDF y JSON)**:
   - Ve a `/reports`, abre **Ver HTML** (prueba filtros por severidad/host/categoría), descarga **PDF** y descarga **JSON (IA)** verificando la estructura de campos (`id`, `timestamp`, `host`, `grupo`, `check`, `categoria`, `severidad`, `titulo`, `descripcion`, `evidencia`, `recomendacion`, `comando_sugerido`, `mitre_id`, `estado`).
