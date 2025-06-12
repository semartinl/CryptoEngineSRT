# ✅ Lista de comprobaciones y tests de actividades

## Actividad 1: [Nombre de la actividad 1]
- [x] Documentar internamente el código al estilo Java (documentación de clase, de atributos y de métodos).
- [x] Interfaz de usuario en modo gráfico
- [x] El 'Contador' a utilizar en los cifrados se generará aleatoriamente y se debe guardar en la cabecera (por tanto, hay que modificar Header.java)
- [x] Crear una función de mida la "calidad" de la contraseña que introduce el usuario, de acuerdo a una escala (por ejemplo,0 a 10). Inventar el procedimiento y describirlo, o bien usar librerías disponibles (por ejemplo, http://devewm.com/projects/pwdstrength).
- [x] Verificar que la passwd que introduce el usuario para DESCIFRAR es correcta antes de usarla, es decir, es la misma que introdujo para cifrar. Para ello:
  - 1.Cifrado:
    - [x] 1.1 Calcular un valor hash (resumen) de la passwd, de 2 bytes .
    - [x] 1.2 Guardar dicho valor en la cabecera (añadir campo a la misma para ello).

  - 2.Descifrado:
    - [x] 2.1 Pedir passwd a usuario y recalcular valor hash.
    - [x] 2.2 Comprobar que coincide con el valor almacenado en la cabecera antes de descifrar.


## Práctica 4: Gestión de claves y cifrado

- [ ] Documentar internamente el código al estilo Java (clases, atributos y métodos) 📝
- [ ] Implementar interfaz de usuario en modo gráfico 🖥️
- [ ] Permitir el uso de claves RSA y DSA 🔑
    - [ ] Validar que con DSA solo se permita firmar/verificar
- [ ] Permitir elegir longitud de claves: 512, 768 o 1024 bits 📏
    - [ ] Ajustar tamaño de bloques según longitud elegida
- [ ] Almacenar claves cifradas en un fichero especificado por el usuario 💾

## Práctica 5: Gestión avanzada de KeyStore

- [ ] Permitir que el KeyStore contenga múltiples claves 🗂️
- [ ] Mostrar todos los alias disponibles en el KeyStore 🏷️
- [ ] Permitir al usuario elegir un alias y especificar su contraseña 🔐