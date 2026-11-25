import jwt from "jsonwebtoken";

export function verificarToken(req, res, next) {
  const autorizacion = req.headers.authorization;

  if (!autorizacion) {
    return res.status(401).json({
      error: "Token requerido"
    });
  }

  const partes = autorizacion.split(" ");

  if (partes.length !== 2 || partes[0] !== "Bearer") {
    return res.status(401).json({
      error: "Formato de token incorrecto. Use Bearer token"
    });
  }

  const token = partes[1];

  try {
    const datos = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.usuario = datos;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Token inválido o vencido"
    });
  }
}

export function soloAdmin(req, res, next) {
  if (req.usuario.rol !== "admin") {
    return res.status(403).json({
      error: "Acceso permitido solamente para administradores"
    });
  }

  next();
}