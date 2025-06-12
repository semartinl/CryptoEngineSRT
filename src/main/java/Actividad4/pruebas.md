## 🔐 Pruebas para práctica de criptografía de clave pública

### Generación y gestión de claves
- [ ] Generar par de claves (pública/privada) con algoritmo elegido (RSA o DSA)
- [ ] Permitir al usuario elegir el tamaño de clave (ej. 512 bits)
- [ ] Guardar el par de claves en un fichero (serialización o codificación + cifrado)
- [ ] Recuperar correctamente las claves desde fichero
- [ ] Acceder correctamente a `getPublic()` y `getPrivate()`

### Firma de ficheros
- [ ] Firmar contenido de fichero con clave privada usando algoritmo elegido (ej. SHA1withRSA)
- [ ] Insertar cabecera en el fichero firmado:
    - [ ] Algoritmo de firma usado
    - [ ] Firma digital generada
- [ ] Confirmar que el contenido original se conserva tras la firma
- [ ] Validar la firma correctamente con la clave pública
- [ ] Verificar que la firma falla si se modifica el contenido original
- [ ] Mostrar mensaje claro de verificación: válida / inválida

### Verificación de firma
- [ ] Extraer firma desde cabecera del fichero firmado
- [ ] Verificar que la firma coincide con el contenido del fichero
- [ ] Recuperar y mostrar contenido original del fichero si la firma es válida
- [ ] Comprobar funcionamiento con diferentes algoritmos de cifrado:
    - [x] SHA224withRSA
    - [x] SHA251withRSA
    - [x] SHA384withRSA
    - [x] SHA512withRSA
    - [x] SHA1withRSA
    - [x] MD2withRSA
    - [x] MD5withRSA
- [ ] Comprobar funcionamiento con diferentes algoritmos de firma:
  - []

### Cifrado de ficheros
- [ ] Cifrar fichero con clave pública usando RSA/ECB/PKCS1Padding
- [ ] Procesar bloques de tamaño adecuado (ej. 53 bytes si clave de 512 bits)
- [ ] Confirmar que el contenido cifrado no puede leerse sin clave privada
- [ ] Guardar archivo cifrado en formato reconocible

### Descifrado de ficheros
- [ ] Descifrar fichero previamente cifrado usando clave privada
- [ ] Procesar bloques de tamaño adecuado en descifrado (ej. 64 bytes)
- [ ] Recuperar exactamente el contenido original tras descifrado
- [ ] Mostrar error si se intenta descifrar con clave incorrecta

### Validación y seguridad
- [ ] Detectar claves mal formateadas o no coincidentes
- [ ] Evitar el uso de claves sin cifrar para almacenamiento (si se requiere seguridad adicional)
- [ ] Verificar que las claves y firmas no se alteran entre sesiones
- [ ] Comprobar integridad de fichero cifrado y firmado

### Casos límite
- [ ] Ficheros vacíos
- [ ] Ficheros grandes que requieren múltiples bloques
- [ ] Ficheros modificados tras ser firmados o cifrados
- [ ] Claves de tamaño no soportado

### Usabilidad
- [ ] Mensajes claros en operaciones exitosas o fallidas
- [ ] Opciones accesibles para elegir algoritmo de firma y cifrado
- [ ] Ficheros de salida correctamente nombrados (`.firmado`, `.cifrado`, etc.)
- [ ] Permitir al usuario seleccionar fichero desde interfaz (si GUI)

### Extra (si aplica)
- [ ] Mostrar firma generada en formato hexadecimal/base64
- [ ] Soporte para múltiples pares de claves (usando alias)
- [ ] Registro/log de acciones realizadas
