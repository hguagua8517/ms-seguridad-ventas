import {AuthenticationBindings, AuthenticationMetadata, AuthenticationStrategy} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {SeguridadUsuarioService} from '../services/seguridadUsuario.service';
import {RolMenuRepository} from './../repositories/rol-menu.repository';


export class AuthStrategy implements AuthenticationStrategy {
  name = 'auth';

  constructor(
    @service(SeguridadUsuarioService)
    private servicioSeguridad: SeguridadUsuarioService,
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata,
    @repository(RolMenuRepository)
    private repositorioRoMenu: RolMenuRepository
      ) {

      }

      /**
       *
       * Autenticación de un usuario frente a una acción en la base de datos
       * @param {Request} request la solicitud del token
       * @returns {(Promise<UserProfile | undefined>)} el perfil de usuario, undefined cuando no tiene permisos o un httpError
       *
       * @memberOf AuthStrategy
       */
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    const token = parseBearerToken(request);
    if (token){
      const idROl = this.servicioSeguridad.obtenerRolDesdeToken(token);
      const idMenu: string = this.metadata.options![0];
      const accion: string = this.metadata.options![1];

      const permiso = await this.repositorioRoMenu.findOne({
        where:{
          rolId: idROl,
          menuId: idMenu
        }
      });
      let continuar = false;
      if (permiso){
        switch(accion){
          case "guardar":
            continuar = permiso.guardar;
            break;
          case "editar":
            continuar = permiso.editar;
            break;
          case "listar":
            continuar = permiso.listar;
            break;
          case "eliminar":
            continuar = permiso.eliminar;
            break;
          case "descargar":
            continuar = permiso.descargar;
            break;
          default:
            throw new HttpErrors[401]("No es posible ejecutar la acción porque no existe.");

        }
        if(continuar){
          const perfil: UserProfile = Object.assign({
            permitido: "ok"
          });
          return perfil;
        }else{
          return undefined;
        }
      }else{
        throw new HttpErrors[401]("No es posible ejecutar la acción por falta de permisos");
      }
    }
    throw new HttpErrors[401]("No es posible ejecutar la acción por falta de token");

 //   console.log('Ejecutando la estrategia');
//return undefined;
  }


}
