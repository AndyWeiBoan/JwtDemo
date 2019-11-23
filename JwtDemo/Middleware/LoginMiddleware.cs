using JwtDemo.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtDemo.Middleware {

    public static class MiddlewareExtnsion {
        public static IApplicationBuilder UseLogin(this IApplicationBuilder app) => app.UseMiddleware<LoginMiddleware>();        
    }

    public class LoginMiddleware {

        private const string PATH = "/Login";

        private readonly RequestDelegate _next;
        private readonly IConfiguration _config;

        public LoginMiddleware(RequestDelegate next, IConfiguration config) {
            this._next = next;
            this._config = config;
        }

        public async Task InvokeAsync(HttpContext context) {
            if (( string.Compare(context.Request.Path, PATH) != 0 )) { 
                await this._next.Invoke(context);
                return;
            }

            if (string.IsNullOrEmpty(context.Request.Form[nameof(User.account)])) {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Error occurred since is required. \r\n");
                return;
            }

            if (string.IsNullOrEmpty(context.Request.Form[nameof(User.password)])) {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Error occurred since password is required. \r\n");
                return;
            }

            if (string.IsNullOrEmpty(context.Request.Form[nameof(User.Email)])) {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Error occurred since Email is required. \r\n");
                return;
            }

            if (string.IsNullOrEmpty(context.Request.Form[nameof(User.Age)])) {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Error occurred since Age is required. \r\n");
                return;
            }

            var account = context.Request.Form[nameof(User.account)].ToString();
            var password = context.Request.Form[nameof(User.password)].ToString();
            var Email = context.Request.Form[nameof(User.Email)].ToString();

            int.TryParse(context.Request.Form[nameof(User.Age)], out var age);

            if (!this.IsUserValid(account, password)) {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("The account not exist or password invalid. \r\n");
                return;
            }

            var user = new User { 
                account = account, 
                password = password,
                Email = Email,
                Age = age
            };

            var claims = this.CreateClaim(user);
            var jwt = this.CreateJWT(claims);
            
            context.Response.StatusCode = 200;

            await context.Response.WriteAsync(jwt);
        }

        private ClaimsIdentity CreateClaim(User u) {
            return new ClaimsIdentity(new[] {
                new Claim(JwtRegisteredClaimNames.NameId, u.account),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, "root"),
                new Claim(ClaimTypes.Email, u.Email),
                new Claim(ClaimTypes.Name, u.account),
                new Claim("Age", u.Age.ToString()),
            });
        }

        private string CreateJWT(ClaimsIdentity claims) {
            var keyBytes = Encoding.UTF8.GetBytes(this._config["JWT:Key"]);
            var issuer = this._config["JWT:Issuer"];
            var securityKey = new SymmetricSecurityKey(keyBytes);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor {
                Issuer = issuer,
                Audience = "AndyWei",
                Subject = claims,
                Expires = DateTime.Now.AddMinutes(30),
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
            };
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(securityToken);
        }

        private bool IsUserValid(string account, string password) {
            if (string.Compare("Andy", account) != 0
                || string.Compare("1234", password, true) != 0) {
                return false;
            }
            return true;
        }
    }
}
