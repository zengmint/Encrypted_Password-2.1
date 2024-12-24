# Encrypted Password Manager 2.1

## Descripción del Proyecto
Este gestor de contraseñas ofrece una solución segura para almacenar y gestionar credenciales. Utiliza el algoritmo de cifrado AES (Advanced Encryption Standard) para proteger los datos y asegura que las contraseñas almacenadas nunca sean visibles en texto plano. Una contraseña maestra controla el acceso a las contraseñas almacenadas.

## Características Principales
- **Cifrado AES**: Cada contraseña es cifrada con una clave única generada mediante una combinación de salt y vector de inicialización (IV).
- **Contraseña Maestra**: Garantiza que solo el usuario autorizado pueda acceder a las contraseñas cifradas.
- **Gestión de Contraseñas**: Añade, visualiza y elimina contraseñas de forma sencilla y segura.
- **Portabilidad**: Compatible con múltiples sistemas operativos.

## Requisitos Previos
Antes de comenzar, asegúrate de que tienes los siguientes elementos instalados en tu sistema:
- Python 3.9 o superior
- Bibliotecas requeridas (ver la sección Instalación)

## Instalación
1. Clona el repositorio desde GitHub:
   ```bash
   git clone https://github.com/zengmint/Encrypted_Password-2.1.git
   cd Encrypted_Password-2.1
   ```

2. Instala las dependencias necesarias utilizando `pip`:
   ```bash
   pip install -r requirements.txt
   ```

3. Ejecuta el programa:
   ```bash
   python Encrypted_Password-2.1.py
   ```

## Uso
1. **Configura tu Contraseña Maestra:**
   - Cada vez que ejecutes el programa, se te pedirá introducir una contraseña maestra. Esta contraseña será necesaria para acceder al gestor.
      (Elige una contraseña maestra segura y colocala cada vez que ingreses al programa,
        ya que las cuentas que crees deberan ser consultadas con dicha contraseña maestra indicada al inicio del programa
        ¡No la olvides o perderas la informacion que ingreses!)

2. **Gestión de Contraseñas:**
   - Agrega una nueva contraseña proporcionando un nombre de servicio, usuario y contraseña.
   - Visualiza contraseñas cifradas introduciendo tu contraseña maestra.
   - Elimina entradas cuando ya no las necesites.

3. **Seguridad de los Datos:**
   - Los datos están cifrados y almacenados localmente. Solo se descifran temporalmente cuando se introducen correctamente la contraseña maestra al iniciar el programa.

## Estructura del Proyecto
```
Encrypted_Password-2.1/
├── main.py              # Archivo principal del programa
├── utils.py             # Funciones auxiliares para cifrado y descifrado
├── database/            # Base de datos para almacenar las contraseñas cifradas
├── requirements.txt     # Dependencias del proyecto
└── README.md            # Documentación del proyecto
```

## Mejoras Futuras
- Interfaz gráfica de usuario (GUI) usando **CustomTkinter**
- Soporte para exportar e importar contraseñas cifradas
- Autenticación de dos factores (2FA) para mayor seguridad
- Integración con servicios de almacenamiento en la nube

## Contribuciones
¡Las contribuciones son bienvenidas! Si tienes ideas para mejorar este proyecto, por favor sigue los pasos a continuación:
1. Haz un fork del repositorio.
2. Crea una nueva rama para tu funcionalidad o mejora:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
3. Haz commit de tus cambios y súbelos a tu rama.
4. Abre un pull request explicando los cambios realizados.

## Licencia
Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## Contacto
Si tienes preguntas o comentarios sobre este proyecto, por favor, contacta a través de [GitHub Issues](https://github.com/zengmint/Encrypted_Password-2.1/issues).

