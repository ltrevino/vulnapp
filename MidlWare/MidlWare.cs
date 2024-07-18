using Microsoft.Extensions.Options;
using VulnerableWebApplication.VLAIdentity;
using VulnerableWebApplication;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace VulnerableWebApplication.MidlWare
{
    public class XRealIPMiddleware
        {
        /*
        Ajoute le Header "X-Real-IP:<IP>" pour les logs de l'application
        */
        private readonly RequestDelegate _next;

        public XRealIPMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            context.Request.Headers["X-Real-IP"] = context.Connection.RemoteIpAddress.ToString();
            await _next(context);
        }

    }


    public class ValidateJwtMiddleware
    {
        private readonly RequestDelegate _next;

        public ValidateJwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }



        public async Task InvokeAsync(HttpContext context, IConfiguration configuration)
        {
            /*
                Authentifie les utilisateurs
            */

            // Si l'URL est celle de l'endpoint de login, on passe à la suite sans valider le token
            var path = context.Request.Path.Value;
            if (path.Equals("/login", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }

            string authHeader = context.Request.Headers["Authorization"];

            if (authHeader.IsNullOrEmpty() || !VLAIdentity.VLAIdentity.VulnerableValidateToken(authHeader, configuration["Secret"]))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }


            //Se agrega el userid
            string token = authHeader.Substring("Bearer ".Length).Trim();
            var userId = ValidateToken(token);

            // Adjuntar el ID del usuario al contexto
            context.Items["UserId"] = userId;
            //FIN CORRECCION
            await _next(context);
        }

        //ACCESO TOKEN Y VALIDACION LATR
        private string ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var jwtToken = tokenHandler.ReadJwtToken(token);

                                                System.Console.Write("=========");

                var userId = jwtToken.Claims.First(x => x.Type == "Id").Value;
                return userId;
            }
            catch
            {
                return null;
            }
        }
    }

}
