using dotnet5_jwt_starter.Api.Authentication;
using dotnet5_jwt_starter.Api.Contracts.V1.Resposes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace dotnet5_jwt_starter.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        #region Declaration
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration _configuration;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly ApplicationDbContext _context;

        public AuthenticateController(UserManager<ApplicationUser> userManager, IConfiguration configuration, TokenValidationParameters tokenValidationParameters, ApplicationDbContext context)
        {
            this.userManager = userManager;
            _configuration = configuration;
            _tokenValidationParameters = tokenValidationParameters;
            _context = context;
        }

        #endregion

        #region EndPoints

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                JwtSecurityToken token = await GenerateToken(user);

                var refreshToken = await SaveRefreshTokenAsync(token, user);

                return Ok(new AuthSuccessResponse
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken.Token
                });
            }
            return Unauthorized();
        }


        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }


        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshAsync(string token, string refreshToken)
        {
            var validatedToken = GetPrincipalFromToken(token);
            if (validatedToken == null)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "Invalid Token" });
            }

            var expiryDateUnix = long.Parse(validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            var expiryDateTimeUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(expiryDateUnix);

            if (expiryDateTimeUtc > DateTime.UtcNow)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "This refresh token hasn't expired yet." });
            }

            var storedRefreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);
            if (storedRefreshToken == null)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "This refresh token doesn't exist." });
            }


            if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "This refresh token is expired." });
            }

            if (storedRefreshToken.invalidated)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "This refresh token is invalidated." });
            }

            if (storedRefreshToken.Used)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "This refresh token has been used." });
            }

            var jti = validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            if (storedRefreshToken.JwtId != jti)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "This refresh token doesn't match this JWT." });
            }

            storedRefreshToken.Used = true;
            _context.RefreshTokens.Update(storedRefreshToken);
            await _context.SaveChangesAsync();

            var user = await userManager.FindByIdAsync(validatedToken.Claims.Single(x => x.Type == ClaimTypes.NameIdentifier).Value);
            if (user == null)
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new Response { Status = "Error", Message = "User not found" });
            }


            JwtSecurityToken newToken = await GenerateToken(user);
            var newRefreshToken = await SaveRefreshTokenAsync(newToken, user);

            return Ok(new AuthSuccessResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(newToken),
                RefreshToken = newRefreshToken.Token
            });
        }

        #endregion

        #region Methods
        private ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, _tokenValidationParameters, out var securityToken);
                if (!IsJwtWithValidSecurityAlgorithm(securityToken))
                {
                    return null;
                }

                return principal;
            }
            catch
            {
                return null;
            }            
        }

        private bool IsJwtWithValidSecurityAlgorithm(SecurityToken securityToken)
        {
            return (securityToken is JwtSecurityToken jwtSecurityToken) && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
        }

        private async Task<JwtSecurityToken> GenerateToken(ApplicationUser user)
        {
            var userRoles = await userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));


            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: GetTokenExpireDate(),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        private async Task<RefreshToken> SaveRefreshTokenAsync(JwtSecurityToken token, ApplicationUser user)
        {
            var refreshToken = new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                JwtId = token.Id,
                UserId = user.Id,
                CreatetionDate = DateTime.UtcNow,
                ExpiryDate = GetRefreshTokenExpireDate()
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return refreshToken;
        }


        private DateTime GetTokenExpireDate()
        {
            DateTime tokenLifeTime = DateTime.Parse(_configuration["JWT:TokenLifeTime"]);
            DateTime expires = DateTime.UtcNow.AddHours(tokenLifeTime.Hour).AddMinutes(tokenLifeTime.Minute).AddSeconds(tokenLifeTime.Second);

            return expires;
        }

        private DateTime GetRefreshTokenExpireDate()
        {
            DateTime tokenLifeTime = DateTime.Parse(_configuration["JWT:TokenLifeTime"]).AddDays(1);
            DateTime expires = DateTime.UtcNow.AddHours(tokenLifeTime.Hour).AddMinutes(tokenLifeTime.Minute).AddSeconds(tokenLifeTime.Second);

            return expires;
        }

        #endregion

    }
}
