### Funcionalidad básica
- [X] Cifrado de archivo con contraseña establecido por el usuario
- [X] Descifrado correcto del archivo con la misma contraseña
- [X] Comprobación de integridad del archivo descifrado (contenido idéntico al original)
- [ ] Comprobar que al realizar un descifrado el proceso sobre el archivo cifrado se cierra.
### Validación de entrada
- [X] Rechazar contraseña vacía o demasiado corta
- [x] Manejo de errores si la contraseña es incorrecta al descifrar
- [x] Manejo de errores si el archivo no existe o está dañado

### Parámetros de seguridad
- [x] Validar que se utiliza una función KDF (como PBKDF2, scrypt, etc.)
- [ ] Confirmar que el número de iteraciones afecta el tiempo de cifrado -> Si que afecta, pero no creo que los vaya a utilizar con muchas iteraciones.
- [x] Confirmar que la contraseña no se almacena en texto plano ni en el archivo

### Usabilidad
- [x] Interfaz clara para introducir contraseña y número de iteraciones
- [ ] Mensajes de éxito o error comprensibles para el usuario
- [ ] Archivo cifrado se guarda con extensión o nombre diferenciado
- [x] Permitir al usuario seleccionar archivos mediante explorador (si es con GUI)

### Casos límite
- [x] Archivos muy pequeños (1 byte)
- [x] Archivos grandes (>100 MB)
- [x] Contraseñas con caracteres especiales y largos (>20 caracteres)
- [x] Número de iteraciones muy bajo y muy alto

### Diferentes algoritmos de cifrado simétrico.
- [x] PBEWithMD5andDES
- [x] PBEWithMD5andTripleDES
- [x] PBEWithSH1AndDESede
- [x] PBEWithSH1AndREC2_40
### Extra (si aplica)
- [ ] Comprobación de tiempo de cifrado/descifrado con distintas iteraciones
- [ ] Pruebas con diferentes algoritmos de cifrado (AES, Blowfish, etc.)
- [ ] Generación y almacenamiento segura de IV (vector de inicialización)