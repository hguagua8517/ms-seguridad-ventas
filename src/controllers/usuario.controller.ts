import {authenticate} from '@loopback/authentication';
import {service} from '@loopback/core';
import {
  Count,
  CountSchema,
  Filter,
  FilterExcludingWhere,
  repository,
  Where,
} from '@loopback/repository';
import {
  del,
  get,
  getModelSchemaRef,
  HttpErrors,
  param,
  patch,
  post,
  put,
  requestBody,
  response,
} from '@loopback/rest';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Usuario} from '../models';
import {Credenciales} from '../models/credenciales.model';
import {UsuarioRepository} from '../repositories';
import {SeguridadUsuarioService} from '../services/seguridadUsuario.service';
import {FactorDeAutenticacionPorCodigo} from './../models/factor-de-autenticacion-por-codigo.model';
import {Login} from './../models/login.model';
import {LoginRepository} from './../repositories/login.repository';

export class UsuarioController {
  constructor(
    @repository(UsuarioRepository)
    public usuarioRepository : UsuarioRepository,
    @service(SeguridadUsuarioService)
    public servicioSeguridad: SeguridadUsuarioService,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) {}

  @post('/usuario')
  @response(200, {
    description: 'Usuario model instance',
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}},
  })
  async create(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {
            title: 'NewUsuario',
            exclude: ['_id'],
          }),
        },
      },
    })
    usuario: Omit<Usuario, '_id'>,
  ): Promise<Usuario> {
    //crear la clave
    const clave = this.servicioSeguridad.crearTextoAleatorio(15);
    console.log(clave);
    //cifrar la clave
    const claveCifrada = this.servicioSeguridad.cifrarTexto(clave);
    //asignar la clave cifrada al usuario
    usuario.clave = claveCifrada;
    //enviar un correo electrónico de notificación
    return this.usuarioRepository.create(usuario);
  }

  @get('/usuario/count')
  @response(200, {
    description: 'Usuario model count',
    content: {'application/json': {schema: CountSchema}},
  })
  async count(
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.count(where);
  }

  @authenticate({
    strategy: "auth",
    options:[ConfiguracionSeguridad.menuUsuarioID, ConfiguracionSeguridad.listarAccion]
  })
  @get('/usuario')
  @response(200, {
    description: 'Array of Usuario model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(Usuario, {includeRelations: true}),
        },
      },
    },
  })
  async find(
    @param.filter(Usuario) filter?: Filter<Usuario>,
  ): Promise<Usuario[]> {
    return this.usuarioRepository.find(filter);
  }

  @patch('/usuario')
  @response(200, {
    description: 'Usuario PATCH success count',
    content: {'application/json': {schema: CountSchema}},
  })
  async updateAll(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.updateAll(usuario, where);
  }

  @get('/usuario/{id}')
  @response(200, {
    description: 'Usuario model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(Usuario, {includeRelations: true}),
      },
    },
  })
  async findById(
    @param.path.string('id') id: string,
    @param.filter(Usuario, {exclude: 'where'}) filter?: FilterExcludingWhere<Usuario>
  ): Promise<Usuario> {
    return this.usuarioRepository.findById(id, filter);
  }

  @patch('/usuario/{id}')
  @response(204, {
    description: 'Usuario PATCH success',
  })
  async updateById(
    @param.path.string('id') id: string,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.updateById(id, usuario);
  }

  @put('/usuario/{id}')
  @response(204, {
    description: 'Usuario PUT success',
  })
  async replaceById(
    @param.path.string('id') id: string,
    @requestBody() usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.replaceById(id, usuario);
  }

  @del('/usuario/{id}')
  @response(204, {
    description: 'Usuario DELETE success',
  })
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.usuarioRepository.deleteById(id);
  }

    /**
   * Métodos personalizados para la API
   */

  @post('/identificar-usuario')
  @response(200, {
    description: "Identificar un usuario por correo y clave",
    content:{'application/json':{schema: getModelSchemaRef(Usuario)}}
  })
  async identificarUsuario(
    @requestBody(
      {
        content: {
          'application/json':{
            schema: getModelSchemaRef(Credenciales)
          }
        }
      }
    )
    credenciales: Credenciales
  ): Promise<object>{
    const usuario = await this.servicioSeguridad.identificarUsuario(credenciales);
    if (usuario) {
      const codigo2fa = this.servicioSeguridad.crearTextoAleatorio(6);
      console.log(codigo2fa);
      const login: Login = new Login();
      login.usuarioId = usuario._id!;
      login.codigo2fa = codigo2fa;
      login.estadoCodigo2fa = false;
      login.token = "";
      login.estadotoken = false;
      // eslint-disable-next-line @typescript-eslint/no-floating-promises
      this.repositorioLogin.create(login);
      usuario.clave = "";
      //notificar al usuario via correo o sns
      return usuario;
    }
    return new HttpErrors[401]("Credenciales incorrectas.")
  }

  @post('/Verificar-2fa')
  @response(200, {
    description: "Validar un código de 2fa",
  })
  async verificarCodigo2fa(
    @requestBody(
      {
        content: {
          'application/json':{
            schema: getModelSchemaRef(FactorDeAutenticacionPorCodigo)
          }
        }
      }
    )
    credenciales: FactorDeAutenticacionPorCodigo
  ): Promise<object>{
    const  usuario = await this.servicioSeguridad.validarCodigo2fa(credenciales);
    if(usuario) {
      const token = this.servicioSeguridad.crearToken(usuario);
      if(usuario){
        usuario.clave ="";
        try{
          // eslint-disable-next-line @typescript-eslint/no-floating-promises
          this.usuarioRepository.logins(usuario._id).patch({
            estadoCodigo2fa: true,
            token: token
          },
          {
            estadoCodigo2fa: false
          });
        //let login = await this.repositorioLogin.findOne({
        //  where: {
        //    usuarioId: usuario._id,
        //    estadoCodigo2fa: false
        //  }
        //});
        //login!.estadoCodigo2fa = true;
        //this.repositorioLogin.updateById(login?._id, login!);
      } catch{
        console.log("No se ha almacenado el cambio del estado del token en la base de datos.")
            }
        return {
          user:  usuario,
          token: token
        };
      }
    }
    return new HttpErrors[401]("Código de 2fa invalido para el usuario definido.");
  }
 }
