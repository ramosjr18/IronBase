# Secure VPS Assessment Module

Este módulo implementa una evaluación de seguridad integral diseñada específicamente para servidores VPS expuestos a internet. A diferencia de un escáner genérico, analiza la postura de seguridad desde dentro (host-based) y simula una visión externa (network-based) para detectar exposiciones riesgosas, configuraciones por defecto peligrosas y vulnerabilidades comunes en despliegues cloud.

## Características

-   **Dual Perspective**: Combina auditoría interna (permisos, kernel, usuarios) con simulación externa (puertos expuestos, IP pública).
-   **No-Ops**: Por defecto es read-only. No modifica el sistema.
-   **Zero Dependency Standalone**: Puede ejecutarse sin instalar todo IronBase, clonando solo este módulo.
-   **Actionable Findings**: Reportes detallados con evidencia, remediación y clasificación por tipo (Misconfiguration, Risk, Vulnerability).

## Cobertura

### Internal Scan (Host-Based)
-   **System**: Versión de Kernel, chequeo de ASLR, directorios con permisos débiles.
-   **Auth**: Usuarios root extra, cuentas sin password, configuración robusta de SSH (Root Login, Password Auth).
-   **Network**: Servicios escuchando en interfaces no-locales (0.0.0.0).

### External Scan (Simulated)
-   **Exposure**: Detección de IP Pública real.
-   **Ports**: Simulación de puertos accesibles desde internet (cruzando data de sockets con IP pública).
-   **Fingerprinting**: Respuesta a ICMP Ping.
-   **Services**: Exposición de SSH en puerto 22 default.

## Uso

### Modo Standalone

Para **clonar y usar solo este módulo** (sin descargar todo IronBase):

```bash
git clone --no-checkout https://github.com/ramosjr18/IronBase.git
cd IronBase
git sparse-checkout init --cone
git sparse-checkout set modules/secure-vps
git checkout
cd modules/secure-vps
```

Una vez en el directorio:

```bash
chmod +x modules/secure-vps/standalone.sh
./modules/secure-vps/standalone.sh
```

### Modo Integrado (IronBase)
Ejecutar a través del engine principal:

```bash
./cmd/ironbase scan --module secure-vps
```

## Interpretación de Resultados

Los hallazgos se clasifican en:
-   **Misconfiguration**: Configuración que se desvía de las mejores prácticas (ej. SSH Root Login enabled).
-   **Vulnerability**: Fallo de seguridad explotable directo (ej. usuario sin password).
-   **Risk Exposure**: Condición que aumenta la superficie de ataque (ej. servicio de base de datos escuchando en 0.0.0.0).

## Limitaciones
-   El escaneo externo es una *simulación* desde el host. No sustituye un escaneo real con Nmap desde una IP externa.
-   La detección de IP pública depende de servicios externos (ifconfig.me / ipify).
