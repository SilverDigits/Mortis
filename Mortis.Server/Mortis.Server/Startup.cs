using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Autofac.Integration.WebApi;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Mortis.Server.Models;
using OpenIddict.Abstractions;
using OpenIddict.Server.Owin;
using OpenIddict.Validation.Owin;
using Owin;

namespace Mortis.Server
{
	public class Startup
	{
		public void Configuration(IAppBuilder app)
		{
			ServiceCollection services = new ServiceCollection();
			services.AddOpenIddict().AddCore([System.Runtime.CompilerServices.NullableContext(1)] (OpenIddictCoreBuilder options) =>
			{
				options.UseEntityFramework().UseDbContext<ApplicationDbContext>();
			}).AddServer([System.Runtime.CompilerServices.NullableContext(1)] (OpenIddictServerBuilder options) =>
			{
				options.SetAuthorizationEndpointUris("connect/authorize").SetLogoutEndpointUris("connect/logout").SetTokenEndpointUris("connect/token");
				options.RegisterScopes("email", "profile", "roles");
				options.AllowAuthorizationCodeFlow();
				options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();
				options.UseOwin().EnableAuthorizationEndpointPassthrough().EnableLogoutEndpointPassthrough()
					.EnableTokenEndpointPassthrough();
			})
				.AddValidation([System.Runtime.CompilerServices.NullableContext(1)] (OpenIddictValidationBuilder options) =>
				{
					options.UseLocalServer();
					options.UseOwin();
				});
			ContainerBuilder builder = new ContainerBuilder();
			builder.Populate(services);
			builder.RegisterControllers(typeof(Startup).Assembly);
			builder.RegisterApiControllers(typeof(Startup).Assembly);
			IContainer container = builder.Build();
			app.CreatePerOwinContext(ApplicationDbContext.Create);
			app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
			app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);
			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AuthenticationType = "ApplicationCookie",
				LoginPath = new PathString("/Account/Login"),
				Provider = new CookieAuthenticationProvider
				{
					OnValidateIdentity = SecurityStampValidator.OnValidateIdentity(TimeSpan.FromMinutes(30.0), (ApplicationUserManager manager, ApplicationUser user) => user.GenerateUserIdentityAsync(manager))
				}
			});
			app.UseExternalSignInCookie("ExternalCookie");
			app.UseTwoFactorSignInCookie("TwoFactorCookie", TimeSpan.FromMinutes(5.0));
			app.UseTwoFactorRememberBrowserCookie("TwoFactorRememberBrowser");
			app.UseAutofacLifetimeScopeInjector(container);
			app.UseMiddlewareFromContainer<OpenIddictServerOwinMiddleware>();
			app.UseMiddlewareFromContainer<OpenIddictValidationOwinMiddleware>();
			DependencyResolver.SetResolver(new AutofacDependencyResolver(container));
			HttpConfiguration configuration = new HttpConfiguration
			{
				DependencyResolver = new AutofacWebApiDependencyResolver(container)
			};
			configuration.MapHttpAttributeRoutes();
			configuration.SuppressDefaultHostAuthentication();
			app.UseAutofacWebApi(configuration);
			app.UseWebApi(configuration);
			Task.Run(async delegate
			{
				ILifetimeScope scope = container.BeginLifetimeScope();
				try
				{
					ApplicationDbContext context = scope.Resolve<ApplicationDbContext>();
					context.Database.CreateIfNotExists();
					IOpenIddictApplicationManager manager2 = scope.Resolve<IOpenIddictApplicationManager>();
					if (await manager2.FindByClientIdAsync("mvc") == null)
					{
						await manager2.CreateAsync(new OpenIddictApplicationDescriptor
						{
							ClientId = "mvc",
							ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
							ConsentType = "explicit",
							DisplayName = "MVC client application",
							RedirectUris = 
							{
								new Uri("https://localhost:44378/callback/login/local")
							},
							PostLogoutRedirectUris = 
							{
								new Uri("https://localhost:44378/callback/logout/local")
							},
							Permissions = { "ept:authorization", "ept:logout", "ept:token", "gt:authorization_code", "rst:code", "scp:email", "scp:profile", "scp:roles" },
							Requirements = { "ft:pkce" }
						});
					}
				}
				finally
				{
					if (scope != null)
					{
						await scope.DisposeAsync();
					}
				}
			}).GetAwaiter().GetResult();
		}
	}
}
