using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using dotnetcoreTokenAuthen.Data;
using dotnetcoreTokenAuthen.Models;
using dotnetcoreTokenAuthen.Services;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography.X509Certificates;

namespace dotnetcoreTokenAuthen
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see https://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets<Startup>();
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(Configuration.GetConnectionString("DefaultConnection"));

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

			// Register the Identity services.
			services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var jwtSigningCert = new X509Certificate2("Path To .pfx or .p12 file", "PutSomePasswordHere");

			// Register the OpenIddict services.
			// Note: use the generic overload if you need
			// to replace the default OpenIddict entities.
			services.AddOpenIddict(options =>
			{
				// Register the Entity Framework stores.
				options.AddEntityFrameworkCoreStores<ApplicationDbContext>();

				// Register the ASP.NET Core MVC binder used by OpenIddict.
				// Note: if you don't call this method, you won't be able to
				// bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
				options.AddMvcBinders();

				// Enable the token endpoint (required to use the password flow).
				options.EnableTokenEndpoint("/connect/token");

                options.UseJsonWebTokens();

				// Allow client applications to use the grant_type=password flow.
				options.AllowPasswordFlow();

                options.AddSigningCertificate(jwtSigningCert);

				// During development, you can disable the HTTPS requirement.
				options.DisableHttpsRequirement();
			});

            services.AddMvc();

            // Add application services.
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, RoleManager<IdentityRole> roleManger)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            InitializeRoles(roleManger);

            app.UseStaticFiles();

            app.UseIdentity();

            app.UseOpenIddict();

            // Add external authentication middleware below. To configure them please see https://go.microsoft.com/fwlink/?LinkID=532715

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

		// Initialize some test roles. In the real world, these would be setup explicitly by a role manager
		private string[] roles = new[] { "User", "Manager", "Administrator" };
		private async Task InitializeRoles(RoleManager<IdentityRole> roleManager)
		{
			foreach (var role in roles)
			{
				if (!await roleManager.RoleExistsAsync(role))
				{
					var newRole = new IdentityRole(role);
					await roleManager.CreateAsync(newRole);
					// In the real world, there might be claims associated with roles
					// _roleManager.AddClaimAsync(newRole, new )
				}
			}
		}
    }
}
