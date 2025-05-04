// Para crear una banco local .json
import DBLocal from "db-local";
// Importa biblioteca para criptografar las contraseñas
import bcrypt from "bcrypt";
// usada para generar ID
import crypto from "crypto"; // Node
// Importando el valor por defecto desde la archivo config para criptografar las contraseñas
import { SALT_ROUNDS } from "./config.js";

// Creacion del banco local en una carpeta db
const { Schema } = new DBLocal({ path: "./db" });

// definiendo los datos del usuario
const User = Schema("User", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});
//  validando los datos de los usuario y las permisiones validas o no
export class UserRepository {
  static async create({ username, password }) {
    // validciones de usuarios
    Validation.username(username);
    Validation.password(password);

    //  asegurar que el username sea unico
    const user = User.findOne({ username });
    if (user) throw new Error("username already exists");
    // generando id aleatorios
    const id = crypto.randomUUID();
    // Generando el codigo para critografar la contraseña
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // creando el usuario, salvandolo e retornando el id
    User.create({
      _id: id,
      username,
      password: hashedPassword,
    }).save();

    return id;
  }
  //  CAMPO PARA VALIDAR EL USUARIO SI EXISTE
  static async login({ username, password }) {
    // validciones de usuarios
    Validation.username(username);
    Validation.password(password);
    // VALIDANDO SI EL USUARIO EXISTE
    const user = User.findOne({ username });
    if (!user) throw new Error("username does not exist");
    // VALIDANDO LA CONTRASENÃ DEL USUARIO
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error("password is invalidad");
    // dejando el password privado
    const { password: _, ...publicUser } = user;

    return publicUser;
  }
}

class Validation {
  static username(username) {
    if (typeof username !== "string")
      throw new Error(
        "username must be a string = nombre de usuario tiene que ser letras"
      );
    if (username.length < 3)
      throw new Error(
        "username must be at least 3 characters long = tiene que tener minimo 3 caracteres"
      );
  }

  static password(password) {
    if (typeof password !== "string")
      throw new Error("Password must be a string = tiene que ser letras ");
    if (password.length < 6)
      throw new Error("Password must be at least 5 characters long ");
  }
}
