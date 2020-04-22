using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleOAuth.Authentication;
using SimpleOAuth.Interfaces;
using SimpleOAuth;
using Microsoft.AspNetCore.Authorization;

namespace test
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddSimpleOAuth(option =>
            {
                option.AddExpireTimeMinutes(10);
                option.AddKeyToken("kl3fj8990asfd123klbvc7m243hjioa90142mkrtdsfd789a");
            });

            services.AddScoped<IAuthorizationRoles, AuthorizationRoles>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseSimpleOAuth();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapPost("/", context => context.LoginOAuth(app));
                endpoints.MapControllers();
            });
        }
    }
}
