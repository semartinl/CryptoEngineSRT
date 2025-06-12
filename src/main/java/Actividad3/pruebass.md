## 🛡️ Pruebas para práctica de integridad con Hash, MAC y HMAC

### Funcionalidad general
- [x] Calcular correctamente el resumen (Hash/MAC/HMAC) del fichero de entrada
- [x] Añadir cabecera al fichero de salida con datos de integridad
- [ ] Comprobar integridad al reabrir el fichero protegido
- [ ] Detectar modificaciones en el contenido y rechazar el fichero alterado
- [ ] Soportar varios algoritmos de resumen seleccionables por el usuario (e.g., SHA-256, HmacSHA1, HmacSHA512)
- [X] MD2
- [x] MD5
- [x] SHA-1
- [x] SHA-384
- [x] SHA-256 
- [x] SHA-512 
- [x] HmacMD5
- [x] HmacSHA1
- [x] HmacSHA256
- [x] HmacSHA384
- [x] HmacSHA512
- [ ] Comprobar que si se ponen el nombre de entrada y salida igual, dar error.
- [ ] Comprobar que los HMAC funcionen con archivos con poco contenido (1 < bytes)
### Parámetros de entrada
- [x] Permitir introducir un valor secreto (contraseña) por parte del usuario
- [x] Generar clave secreta a partir de la contraseña con PBKDF2 (cuando sea necesario)
- [x] Solicitar y validar el algoritmo de resumen seleccionado por el usuario
- [x] Validar longitud de clave, número de iteraciones y salt cuando se use HMAC

### Comprobaciones de integridad
- [x] Comprobar que el resumen calculado coincide con el almacenado en la cabecera
- [ ] Rechazar archivos modificados (incluso 1 byte)
- [ ] Rechazar archivos con cabecera incorrecta o inexistente
- [ ] Comprobar correcto parseo de la cabecera en distintos casos

### Algoritmos soportados
- [x] Validar funcionamiento con MessageDigest (SHA-1, SHA-256, etc.)
- [x] Validar funcionamiento con MAC (HmacSHA1, HmacSHA256, etc.)
- [ ] Validar funcionamiento con DigestInputStream (flujo hash)
- [ ] Verificar correcta generación del `Mac` con clave derivada por `PBKDF2`

### Seguridad
- [ ] Confirmar que el valor secreto nunca se guarda en texto plano
- [ ] Validar que el resumen no puede falsificarse sin el secreto
- [ ] Uso de salt aleatorio para derivación de claves
- [ ] Comprobación del número de iteraciones en PBKDF2

### Casos límite
- [ ] Archivos vacíos
- [ ] Archivos muy grandes (>100 MB)
- [ ] Contraseñas cortas o muy largas
- [ ] Algoritmo inválido (probar con valores no soportados)
- [ ] Fichero sin cabecera o con cabecera corrupta

### Usabilidad
- [ ] Mensajes claros al verificar integridad: "válido" o "modificado"
- [ ] Interfaz clara para selección de algoritmo, entrada de contraseña, número de iteraciones y salt
- [ ] Permitir seleccionar archivo desde explorador (si tiene GUI)
- [ ] Diferenciar archivo original del protegido mediante nombre o extensión

### Extra (si aplica)
- [ ] Mostrar resumen calculado en hexadecimal al usuario
- [ ] Generar log de operaciones realizadas
- [ ] Opción para usar resumen como "firma digital informal"