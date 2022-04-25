using System.Collections.Generic;

namespace bs_JWT.Models
{
    public class AuthResult
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public bool Success { get; set; }
    }   
}