import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales} from '../models/credenciales.model';
import {FactorDeAutenticacionPorCodigo} from '../models/factor-de-autenticacion-por-codigo.model';
import {Usuario} from '../models/usuario.model';
import {UsuarioRepository} from '../repositories/usuario.repository';
import {LoginRepository} from './../repositories/login.repository';
const generator = require('generate-password');
const MD5 = require("crypto-js/md5");
const  jwt = require('jsonwebtoken');
@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) {}

/**
 *
 * Crear una clave aleatoria
 * @returns {string} cadena aleatoria de n caracteres
 *
 * @memberOf SeguridadUsuarioService
 */
  crearTextoAleatorio(n: number): string{
    const clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave;
  }

/**
 *
 *  Cifrar una cadena con método md5
 * @param {string} cadena texto a cifrar
 * @returns {string} cadena cifrada con md5
 *
 * @memberOf SeguridadUsuarioService
 */
  cifrarTexto(cadena: string): string{
     const cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * *
   * Se busca un usuario por sus credenciales de acceso
   * @param {Credenciales} credenciales credenciales del usuario
   * @returns {(Promise<Usuario | null>)} usuario encontrado o null
   *
   * @memberOf SeguridadUsuarioService
   */
  async identificarUsuario(credenciales: Credenciales): Promise<Usuario | null>{
    const usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    });
    return usuario as Usuario;
  }


  /**
   *
   * Valida un código de 2fa para un usuario
   * @param {FactorDeAutenticacionPorCodigo} credencialesCodigo2fa credenciales del usuario con el código del 2fa
   * @returns {(Promise<Login | null>)} el registro de login o null
   *
   * @memberOf SeguridadUsuarioService
   */
  async validarCodigo2fa(credencialesCodigo2fa: FactorDeAutenticacionPorCodigo): Promise<Usuario | null>{
    const login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credencialesCodigo2fa.usuarioId,
        codigo2fa: credencialesCodigo2fa.codigo2fa,
        estadoCodigo2fa: false
      }
    });

    if (login){
     const usuario = this.repositorioUsuario.findById(credencialesCodigo2fa.usuarioId);
     return usuario;
    }
    return null;
  }

  /**
   *
   * Generación de JWT
   * @param {Usuario} usuario informacion del usuario
   * @returns {string} token
   *
   * @memberOf SeguridadUsuarioService
   */
  crearToken(usuario: Usuario): string {
  const datos = {
    name: `${usuario.primeNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`,
    role: usuario.rolId,
    email: usuario.correo
};
    const token = jwt.sign( datos, ConfiguracionSeguridad.claveJWT);
 return token;

  }

  /**
   *
   * Valida y obtiene el rol de un token
   * @param {string} tk el token
   * @returns {string} el id del rol
   *
   * @memberOf SeguridadUsuarioService
   */
  obtenerRolDesdeToken(tk: string): string{
    const obj = jwt.verify(tk, ConfiguracionSeguridad.claveJWT)
    return obj.role;
  }
}

