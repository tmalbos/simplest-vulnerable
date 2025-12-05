<?php
// Conexi1n a la base de datos (modifica con tus propios par1metros de conexi1n)
$servername = "localhost";
$username = "tu_usuario";
$password = "tu_contrase1a";
$dbname = "tu_base_de_datos";

// Crear conexi1n
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar conexi1n
if ($conn->connect_error) {
    // No revelar detalles internos al usuario; registrar el error y mostrar un mensaje gen1rico
    error_log("DB connection error: " . $conn->connect_error);
    die("Error de conexi1n. Por favor contacte al administrador.");
}

// Mitigaci1n de SQL Injection
// Usar sentencias preparadas con enlace de par1metros en lugar de concatenar entrada del usuario.
if (isset($_GET['id'])) {
    // Validar y sanitizar: permitir s1lo un entero positivo
    if (!ctype_digit($_GET['id'])) {
        echo "ID inv1lido.";
    } else {
        $id = (int) $_GET['id']; // casteo seguro a entero

        // Preparar la consulta usando parámetros
        if ($stmt = $conn->prepare("SELECT id, nombre FROM usuarios WHERE id = ?")) {
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows > 0) {
                while ($row = $result->fetch_assoc()) {
                    // Mitigaci1n de XSS: escapar cualquier salida que provenga de la base de datos
                    $safe_id = htmlspecialchars($row['id'], ENT_QUOTES, 'UTF-8');
                    $safe_nombre = htmlspecialchars($row['nombre'], ENT_QUOTES, 'UTF-8');
                    echo "id: " . $safe_id . " - Nombre: " . $safe_nombre . "<br>";
                }
            } else {
                echo "0 resultados";
            }

            $stmt->close();
        } else {
            // No exponer la consulta ni detalles del error al usuario
            error_log("Prepare failed: " . $conn->error);
            echo "Error al ejecutar la consulta.";
        }
    }
}

// Mitigaci1n de Cross-Site Scripting (XSS) para mensajes proporcionados por el usuario
if (isset($_GET['mensaje'])) {
    $mensaje = $_GET['mensaje'];
    // Escapar antes de imprimir para evitar XSS
    echo "<div>" . htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8') . "</div>";
}

// Cerrar conexion
$conn->close();
?>
