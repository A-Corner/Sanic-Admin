# SA-Admin

Construido sobre **Sanic** y aprovechando el framework low-code **AMIS** para el frontend, SA-Admin simplifica la configuración del frontend para los desarrolladores de backend. Con la potencia y naturaleza ligera de Sanic, permite que el gestor de backend cubra un rango más amplio y logre una funcionalidad más robusta.

<img src="./Readme_image2.jpeg" alt="Readme_image1" style="zoom:25%;" />

<img src="./Readme_image3.png" alt="Readme_image1" style="zoom: 25%;" />

<img src="./Readme_image4.png" alt="Readme_image1" style="zoom:25%;" />

<img src="./Readme_image5.png" alt="Readme_image1" style="zoom:25%;" />

## Instalación

Actualmente, no hay un método de instalación disponible a través de PyPI. Puedes clonar el repositorio en tu entorno local y ejecutarlo directamente:

```python
python3 main.py
```

Esto ejecutará y depurará la aplicación.

## Uso

Para utilizar SA-Admin, necesitas tener conocimientos básicos de Sanic o Flask. El framework está basado laxamente en Django y utiliza Tortoise ORM, plantillas Jinja2, y el frontend está construido con el framework low-code de Baidu, AMIS. AMIS es un framework de frontend conveniente, pero puede requerir algo de tiempo para familiarizarse con él. Con AMIS, puedes controlar las páginas del frontend directamente utilizando JSON.

El código incluye comentarios a los que puedes referirte directamente.

Uso específico:

1. Configuración de la Base de Datos

   La configuración de la base de datos se encuentra en el archivo `main.py`. Si necesitas cambiar a una base de datos diferente, se recomienda cambiar a MySQL o PostgreSQL ya que Tortoise soporta llamadas asíncronas a estas dos bases de datos directamente, y la velocidad es realmente impresionante.

   ```python
   sa_config.TEST_DATABASE_URL = "sqlite://security_test_db.sqlite3"
   ```

2. Configuración del Administrador

   La contraseña inicial para el administrador es `SAdmin: SAdmin@123`. Si necesitas cambiarla por tu propia contraseña, modifica el parámetro.

   ```python
   sa_config.INITIAL_ADMIN_PASSWORD = "SAdmin@123"  # Contraseña utilizada al crear la cuenta de administrador inicial
   ```

3. Configurar el puerto y ejecutar el comando

   Si es necesario, puedes cambiar el puerto:

   ```python
   app.run(
       host="127.0.0.1",
       port=22222,
       workers=1,
       debug=True,
       auto_reload=True
   )
   ```

   Explicación de los comandos:

   - `workers=1`: Esto configura el procesamiento multitarea. Sin embargo, en situaciones de alta concurrencia, debido al tiempo que consume el cambio entre operaciones paralelas y asíncronas, puede ser más lento que una instancia única. Si es necesario, se recomienda ejecutar múltiples procesos, pero por ahora es mejor no usar `workers`. La elección depende del escenario real.

   - `auto_reload=True`: Esto habilita la recarga automática, lo cual es muy útil. No necesitas recargar manualmente cuando realices cambios en el código.

4. Diseñar el frontend AMIS usando un editor

   La primera vez que uses AMIS, tómate un tiempo para leer la documentación de AMIS y entender cómo usar sus componentes. Yo pasé tres días leyendo la documentación y familiarizándome con los diversos componentes.

   Puedes usar directamente el editor en línea de AMIS para el diseño de la interfaz:

   Editor de AMIS:

   [https://aisuda.github.io/amis-editor-demo/#/hello-world](https://aisuda.github.io/amis-editor-demo/#/hello-world)

   <img src="./Readme_image6.png" alt="Readme_image1" style="zoom:25%;" />

5. Editar los componentes del frontend y copiar el código directamente.

   <img src="./Readme_image1.png" alt="Readme_image1" style="zoom:33%;" />

6. En el área de código del frontend, crea un archivo JSON y pega el código.

7. Referenciar el código recién creado en el framework principal.

   El archivo del framework principal es `./admin/pages/site.json`. Para modificarlo y referenciarlo:

   - Copia todo el código del framework principal.
   - Ve al editor de AMIS, crea una página nueva, pega el código y añade una columna según tus preferencias.
   - Después de editar, cópialo de vuelta en `site.json`. Modifica la sección `data` a `"schema": {}`, que representa el contenido en el lado derecho de la página.

También puedes seguir mi enfoque guardando el contenido de la página recién añadida como un archivo JSON separado y referenciándolo mediante `schemaApi`. Consulta el archivo `site.json` para más detalles.

A continuación se muestra el formato JSON para AMIS:

```json
{
  "status": 0,  // Elemento requerido en la respuesta
  "msg": "",    // Elemento requerido en la respuesta
  "data": {     // JSON que representa los elementos de la página
    "pages": [
      {           // Capa de título para la barra de navegación
        "label": "Home",
        "url": "/",  // URL para esta capa para facilitar la navegación a otras capas
        "redirect": "/login"  // A qué página navegar cuando la página se inicializa
      },
      {
        "label": "Function Navigation",  // Esta capa se convierte en la barra de navegación
        "children": [                   // Capa de columnas para la barra de navegación
          {
            "label": "Login/Register",
            "url": "login",
            "schema": {}  // El contenido aquí representa el contenido en el lado derecho de la página
          },
          {
            "label": "The number of items here represents the number of columns in the navigation bar",
            "url": "login",
            "schema": {}  // El contenido aquí representa el contenido en el lado derecho de la página
          }
        ]
      }
    ]
  }
}
```

## Notas Finales

Esta es una interfaz sencilla de gestión administrativa. Por favor, modifícala según tus necesidades específicas. Con las características de AMIS, se puede cubrir aproximadamente el 90% de los requerimientos de las interfaces de gestión administrativa. Para el 10% restante, es posible que necesites ayuda de un desarrollador de UI frontend.

### Notas de Rendimiento

Lo probé con ApiPost7, pero los resultados no fueron tan ideales como otros han afirmado. Podría deberse al uso de múltiples workers. Escribí una prueba de solicitud asíncrona de 60 segundos [./test/access_url.pu], y el número aproximado de solicitudes manejadas por un proceso está entre 20,000 y 26,000, sin pérdida de paquetes. La tasa de solicitudes es de aproximadamente 400 solicitudes por segundo bajo el procesamiento de Sanic.

Cuando ejecuté tres procesos simultáneamente, el número de solicitudes simultáneas bajó a unas 14,000, por lo que no estoy seguro de si se debe a limitaciones de recursos de mi portátil (Macbook14 M1) o a algo más. Si tienes recursos suficientes, puedes usar mi código o mejorarlo y realizar más pruebas. En promedio, es una carga de estrés de unas 2,300 solicitudes por segundo, lo cual considero bastante bueno para un panel de administración.

<img src="./Readme_image7.png" alt="Readme_image7" style="zoom:33%;" />

Cuando ejecuté diez procesos, el número de solicitudes simultáneas se mantuvo en torno a 14,000, sin errores.

<img src="./Readme_image8.png" alt="Readme_image8" style="zoom:33%;" />
