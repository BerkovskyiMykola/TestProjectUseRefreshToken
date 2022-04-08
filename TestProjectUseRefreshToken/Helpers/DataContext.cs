namespace TestProjectUseRefreshToken.Helpers;

using Microsoft.EntityFrameworkCore;
using TestProjectUseRefreshToken.Entities;

public class DataContext : DbContext
{
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    private readonly IConfiguration Configuration;

    public DataContext(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        // connect to SqlServer database
        options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));
    }
}