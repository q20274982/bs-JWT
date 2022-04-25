using Microsoft.EntityFrameworkCore;

namespace bs_JWT.Models
{
    public class JWTContext : DbContext
    {
        public JWTContext(DbContextOptions<JWTContext> options) : base(options)
        {
            
        }

        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}