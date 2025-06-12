## 🔐 Pruebas para práctica con Java KeyStore (JKS)

### Carga y acceso al KeyStore
- [ ] Especificar correctamente el fichero del KeyStore (`.jks`)
- [ ] Introducir y validar contraseña principal de acceso
- [ ] Cargar el KeyStore en Java con `KeyStore.getInstance("JKS")`
- [ ] Leer correctamente desde fichero con `FileInputStream`
- [ ] Mostrar error claro si la contraseña o el fichero son incorrectos

### Visualización del contenido del KeyStore
- [ ] Listar todos los alias contenidos en el KeyStore
- [ ] Identificar correctamente si el alias contiene una clave privada (`isKeyEntry`)
- [ ] Obtener clave privada usando `getKey(alias, contraseñaAlias)`
- [ ] Obtener certificado y clave pública usando `getCertificate(alias).getPublicKey()`
- [ ] Mostrar alias, tipo de clave y detalles básicos del certificado

### Importación de claves al entorno del programa
- [ ] Importar par de claves (privada/pública) desde un alias existente en el KeyStore
- [ ] Comprobar disponibilidad de claves para firma o cifrado
- [ ] Manejar errores si el alias no existe o está protegido por contraseña incorrecta

### Generación de claves y certificado con `keytool`
- [ ] Generar correctamente un par de claves RSA (512 bits) con `keytool`
- [ ] Firmar localmente con datos reales del usuario
- [ ] Verificar que el alias aparece correctamente en el KeyStore
- [ ] Confirmar que la clave está protegida por contraseña y se puede recuperar

### Funcionalidad opcional: gestión completa del KeyStore
- [ ] Crear nuevo KeyStore desde Java (almacén vacío con contraseña)
- [ ] Crear par de claves RSA (512 bits) y generar certificado
- [ ] Almacenar el par en el KeyStore bajo un alias y contraseña
- [ ] Mostrar contenido actualizado tras inserción
- [ ] Seleccionar alias y recuperar claves para uso en la aplicación
- [ ] Eliminar una entrada del KeyStore por su alias
- [ ] Confirmar eliminación correcta (alias ya no aparece)

### Usabilidad y validaciones
- [ ] Interfaz para seleccionar archivo `.jks` (si es GUI)
- [ ] Validación de contraseñas vacías o incorrectas
- [ ] Confirmación al importar, crear o eliminar claves
- [ ] Mensajes claros de éxito o error en cada operación

### Seguridad
- [ ] Las claves privadas deben mantenerse cifradas dentro del KeyStore
- [ ] El KeyStore debe requerir contraseña para cualquier operación sensible
- [ ] Mostrar advertencia si se trabaja con claves sin protección

### Extra (si aplica)
- [ ] Integración con KeyStore Explorer para visualización y edición externa
- [ ] Permitir exportar el certificado público a un fichero `.cer`
- [ ] Registro de operaciones realizadas en un log interno
