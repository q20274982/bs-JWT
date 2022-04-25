using System.IO;
using System.ComponentModel;
using System;
using bs_JWT.Helper;
using bs_JWT.Models;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace bs_JWT.Controllers
{
    public class TokenController : ControllerBase
    {
        private readonly JwtHelper _jwt;


        public TokenController(JwtHelper jwt)
        {
            _jwt = jwt;
        }

        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<IActionResult> SignIn(LoginVM query)
        {
            if (ValidateUser(query))
            {
                return Ok(await _jwt.GenerateToken(query.Username));
            }

            return BadRequest();
        }

        [AllowAnonymous]
        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken(TokenRequest query)
        {
            var rt = _jwt.GetRefreshToken(query.RefreshToken);

            if (rt == null) return BadRequest();

            return Ok(await _jwt.GenerateToken(rt.Username));
        }

        [Authorize(Roles="Users")]
        [HttpGet("claims")]
        public IActionResult GetClaims()
        {
            return Ok(User.Claims.Select(x => new { x.Type, x.Value }));
        }

        [Authorize(Roles="SuperAdmin")]
        [HttpGet("username")]
        public IActionResult GetuserName()
        {
            return Ok(User.Identity.Name);
        }

        [HttpGet("jtwid")]
        public IActionResult GetUniqeId()
        {
            var jti = User.Claims.FirstOrDefault(x => x.Type == "jti");
            return Ok(jti.Value);
        }

        private bool ValidateUser(LoginVM login)
        {
            return true;
        }
    }
}