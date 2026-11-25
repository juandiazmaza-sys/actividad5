import "dotenv/config";
import express from "express";
import { db } from "./db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import {
  verificarToken,
  soloAdmin
} from "./middlewares.js";

const app = express();
const PORT = 3000;

app.use(express.json());

// Verificar conexión con MySQL
try {
  await db.query("SELECT 1");
  console.log("✅ Conexión exitosa a MySQL");
} catch (error) {
  console.error("❌ Error de conexión a MySQL:");
  console.error(error.message);
}

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      email.trim() === "" ||
      typeof password !== "string" ||
      password.trim() === ""
    ) {
      return res.status(400).json({
        error: "El email y la contraseña son obligatorios"
      });
    }

    const [usuarios] = await db.query(
      "SELECT * FROM usuarios WHERE email = ?",
      [email.trim()]
    );

    if (usuarios.length === 0) {
      return res.status(401).json({
        error: "Email o clave incorrectos"
      });
    }

    const usuario = usuarios[0];

    const coincide = await bcrypt.compare(
      password,
      usuario.password
    );

    if (!coincide) {
      return res.status(401).json({
        error: "Email o clave incorrectos"
      });
    }

    const token = jwt.sign(
      {
        id: usuario.id,
        rol: usuario.rol
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h"
      }
    );

    res.status(200).json({
      mensaje: "Inicio de sesión correcto",
      token
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Error durante el inicio de sesión"
    });
  }
});

// PERFIL
app.get("/perfil", verificarToken, (req, res) => {
  res.status(200).json({
    mensaje: "Acceso autorizado",
    usuario: req.usuario
  });
});

// GET TODOS LOS PRODUCTOS
app.get("/productos", async (req, res) => {
  try {
    const [productos] = await db.query(
      "SELECT * FROM productos"
    );

    const productosFormateados = productos.map((producto) => ({
      nombre: producto.nombre,
      precio: Number(producto.precio),
      stock: producto.stock
    }));

    res.status(200).json(productosFormateados);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Error al consultar los productos"
    });
  }
});

// GET PRODUCTO POR ID
app.get("/productos/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "El ID debe ser un número entero positivo"
      });
    }

    const [productos] = await db.query(
      "SELECT * FROM productos WHERE id = ?",
      [id]
    );

    if (productos.length === 0) {
      return res.status(404).json({
        error: "Producto no encontrado"
      });
    }

    res.status(200).json({
      nombre: productos[0].nombre,
      precio: Number(productos[0].precio),
      stock: productos[0].stock
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Error al consultar el producto"
    });
  }
});

// POST PRODUCTO
app.post(
  "/productos",
  verificarToken,
  soloAdmin,
  async (req, res) => {
    try {
      const { nombre, precio, stock = 0 } = req.body;

      if (
        typeof nombre !== "string" ||
        nombre.trim() === "" ||
        typeof precio !== "number" ||
        precio < 0 ||
        typeof stock !== "number" ||
        !Number.isInteger(stock) ||
        stock < 0
      ) {
        return res.status(400).json({
          error: "Nombre, precio o stock no son válidos"
        });
      }

      await db.query(
        "INSERT INTO productos (nombre, precio, stock) VALUES (?, ?, ?)",
        [nombre.trim(), precio, stock]
      );

      res.status(201).json({
        nombre: nombre.trim(),
        precio,
        stock
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Error al crear el producto"
      });
    }
  }
);

// PUT PRODUCTO
app.put(
  "/productos/:id",
  verificarToken,
  soloAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { nombre, precio, stock } = req.body;

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "El ID debe ser un número entero positivo"
        });
      }

      if (
        typeof nombre !== "string" ||
        nombre.trim() === "" ||
        typeof precio !== "number" ||
        precio < 0 ||
        typeof stock !== "number" ||
        !Number.isInteger(stock) ||
        stock < 0
      ) {
        return res.status(400).json({
          error: "Debe enviar nombre, precio y stock válidos"
        });
      }

      const [resultado] = await db.query(
        `UPDATE productos
         SET nombre = ?, precio = ?, stock = ?
         WHERE id = ?`,
        [nombre.trim(), precio, stock, id]
      );

      if (resultado.affectedRows === 0) {
        return res.status(404).json({
          error: "Producto no encontrado"
        });
      }

      res.status(200).json({
        nombre: nombre.trim(),
        precio,
        stock
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Error al actualizar el producto"
      });
    }
  }
);


// PATCH PRODUCTO
app.patch(
  "/productos/:id",
  verificarToken,
  soloAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const camposRecibidos = Object.keys(req.body);

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "El ID debe ser un número entero positivo"
        });
      }

      if (camposRecibidos.length === 0) {
        return res.status(400).json({
          error: "Debe enviar al menos un campo para actualizar"
        });
      }

      const [productos] = await db.query(
        "SELECT * FROM productos WHERE id = ?",
        [id]
      );

      console.log("ID:", id);
      console.log("PRODUCTO:", productos);

      if (productos.length === 0) {
        return res.status(404).json({
          error: "Producto no encontrado"
        });
      }

      const actual = productos[0];

      const nombre =
        req.body.nombre ?? actual.nombre;

      const precio =
        req.body.precio ?? Number(actual.precio);

      const stock =
        req.body.stock ?? actual.stock;

      if (
        typeof nombre !== "string" ||
        nombre.trim() === "" ||
        typeof precio !== "number" ||
        precio < 0 ||
        typeof stock !== "number" ||
        !Number.isInteger(stock) ||
        stock < 0
      ) {
        return res.status(400).json({
          error: "Debe enviar nombre, precio o stock válidos"
        });
      }

      await db.query(
        `UPDATE productos
         SET nombre = ?, precio = ?, stock = ?
         WHERE id = ?`,
        [nombre.trim(), precio, stock, id]
      );

      res.status(200).json({
        nombre: nombre.trim(),
        precio,
        stock
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Error al modificar el producto"
      });
    }
  }
);

// DELETE PRODUCTO
app.delete(
  "/productos/:id",
  verificarToken,
  soloAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const [resultado] = await db.query(
        "DELETE FROM productos WHERE id = ?",
        [id]
      );

      if (resultado.affectedRows === 0) {
        return res.status(404).json({
          error: "Producto no encontrado"
        });
      }

      res.status(200).json({
        mensaje: "Producto eliminado correctamente"
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Error al eliminar el producto"
      });
    }
  }
);

app.listen(PORT, () => {
  console.log(`Servidor en puerto ${PORT}`);
});